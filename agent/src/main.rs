use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const INTERVAL: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Identity {
    agent_uuid: String,
    auth_token: String,
    signing_key: String,
}

#[derive(Serialize, Deserialize)]
struct State {
    console: String,
    identity: Identity,
    seq: u64,
    pending: Option<Value>,
}

#[derive(Clone, PartialEq, Serialize)]
struct Connection {
    kind: String,
    local_address: String,
    remote_address: String,
    state: String,
    inode: u64,
    observed_at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn save(path: &Path, state: &State) -> Result<()> {
    let parent = path.parent().ok_or("Invalid state path")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn endpoint(value: &str, ipv6: bool) -> Result<String> {
    let (host, port) = value.split_once(':').ok_or("Missing socket port")?;
    let port = u16::from_str_radix(port, 16)?;
    if ipv6 {
        if host.len() != 32 {
            return Err("Invalid IPv6 address".into());
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&u32::from_str_radix(&host[i * 8..i * 8 + 8], 16)?.to_ne_bytes());
        }
        Ok(format!("[{}]:{}", Ipv6Addr::from(bytes), port))
    } else {
        let bytes = u32::from_str_radix(host, 16)?.to_ne_bytes();
        Ok(format!("{}:{}", Ipv4Addr::from(bytes), port))
    }
}

fn connections() -> Result<BTreeMap<String, Connection>> {
    let mut result = BTreeMap::new();
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if ipv6 && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for line in BufReader::new(file).lines().skip(1) {
            let line = line?;
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] == "0A" {
                continue;
            }
            let local_address = endpoint(fields[1], ipv6)?;
            let remote_address = endpoint(fields[2], ipv6)?;
            let inode = fields[9].parse()?;
            let key = format!("{local_address}/{remote_address}/{inode}");
            result.insert(
                key,
                Connection {
                    kind: "connection".into(),
                    local_address,
                    remote_address,
                    state: fields[3].to_owned(),
                    inode,
                    observed_at: now(),
                },
            );
            if result.len() >= 256 {
                return Ok(result);
            }
        }
    }
    Ok(result)
}

fn memory_field(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != name {
                return None;
            }
            parts.next()?.parse::<u64>().ok().map(|value| value * 1024)
        })
        .unwrap_or(0)
}

fn resources() -> Result<Value> {
    let memory = fs::read_to_string("/proc/meminfo")?;
    let status = fs::read_to_string("/proc/self/status")?;
    let load: f64 = fs::read_to_string("/proc/loadavg")?
        .split_whitespace()
        .next()
        .ok_or("Missing load")?
        .parse()?;
    Ok(
        json!({"load_1": load, "memory_total_bytes": memory_field(&memory, "MemTotal:"),
        "memory_available_bytes": memory_field(&memory, "MemAvailable:"),
        "agent_rss_bytes": memory_field(&status, "VmRSS:")}),
    )
}

fn post(
    client: &ureq::Agent,
    console: &str,
    route: &str,
    payload: &Value,
    identity: Option<&Identity>,
) -> Result<Value> {
    let raw = serde_json::to_vec(payload)?;
    let mut request = client
        .post(format!("{console}/api/agent/{route}"))
        .header("Content-Type", "application/json");
    if let Some(identity) = identity {
        let timestamp = now().to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(&hex::decode(&identity.signing_key)?)?;
        mac.update(timestamp.as_bytes());
        mac.update(b"\n");
        mac.update(&raw);
        request = request
            .header("Authorization", format!("Bearer {}", identity.auth_token))
            .header("X-Agent-UUID", &identity.agent_uuid)
            .header("X-Agent-Timestamp", timestamp)
            .header(
                "X-Agent-Signature",
                hex::encode(mac.finalize().into_bytes()),
            );
    }
    Ok(request.send(raw)?.body_mut().read_json::<Value>()?)
}

fn run() -> Result<()> {
    if env::args().any(|arg| arg == "--version") {
        println!("panopticon-agent {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let console = env::var("PANOPTICON_CONSOLE_URL")?
        .trim_end_matches('/')
        .to_owned();
    // Plain HTTP is limited to a local development console.
    let uri: ureq::http::Uri = console.parse()?;
    let local = matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(uri.scheme_str() == Some("https") || (uri.scheme_str() == Some("http") && local))
        || uri.host().is_none()
        || uri.path() != "/"
        || console.contains(['?', '#', '@', '\n', '\r'])
    {
        return Err("Console URL requires HTTPS or loopback HTTP".into());
    }
    let directory = PathBuf::from(
        env::var("PANOPTICON_STATE_DIR").unwrap_or_else(|_| "/var/lib/panopticon-agent".into()),
    );
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    // An advisory lock also releases automatically after a crash.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join("agent.lock"))?;
    lock.try_lock()?;
    let path = directory.join("state.json");
    let client: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .max_redirects(0)
        .build()
        .into();
    let mut state: State = if path.exists() {
        let state: State = serde_json::from_slice(&fs::read(&path)?)?;
        if state.console != console {
            return Err("State belongs to a different console".into());
        }
        state
    } else {
        let token = env::var("PANOPTICON_ENROLLMENT_TOKEN")?;
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?
            .trim()
            .to_owned();
        let platform = format!("linux/{}", env::consts::ARCH);
        let response = post(
            &client,
            &console,
            "enroll",
            &json!({"enrollment_token": token, "hostname": hostname, "platform": platform}),
            None,
        )?;
        let state = State {
            console: console.clone(),
            identity: serde_json::from_value(response)?,
            seq: 0,
            pending: None,
        };
        save(&path, &state)?;
        state
    };
    let mut previous: BTreeMap<String, Connection> = BTreeMap::new();
    let mut latency_ms = 0.0;
    loop {
        let tick = Instant::now();
        let heartbeat = json!({"agent_uuid": state.identity.agent_uuid, "latency_ms": latency_ms, "resources": resources()?});
        let start = Instant::now();
        if post(
            &client,
            &console,
            "heartbeat",
            &heartbeat,
            Some(&state.identity),
        )
        .is_ok()
        {
            latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        } else {
            eprintln!("Heartbeat delivery failed; retrying on next interval");
        }
        if state.pending.is_none() {
            let current = connections()?;
            let mut events = Vec::new();
            for (key, connection) in &current {
                if previous
                    .get(key)
                    .is_none_or(|old| old.state != connection.state)
                {
                    events.push(connection.clone());
                }
            }
            for (key, connection) in &previous {
                if events.len() >= 256 {
                    break;
                }
                if !current.contains_key(key) {
                    let mut closed = connection.clone();
                    closed.state = "closed".into();
                    closed.observed_at = now();
                    events.push(closed);
                }
            }
            previous = current;
            if !events.is_empty() {
                state.pending = Some(
                    json!({"agent_uuid": state.identity.agent_uuid, "seq": state.seq + 1, "events": events}),
                );
                save(&path, &state)?;
            }
        }
        if let Some(payload) = &state.pending {
            match post(&client, &console, "events", payload, Some(&state.identity)) {
                Ok(response)
                    if response["ok"] == true
                        && response["seq"].as_u64() == Some(state.seq + 1) =>
                {
                    state.seq += 1;
                    state.pending = None;
                    save(&path, &state)?;
                }
                _ => eprintln!("Event delivery failed; retaining pending sequence"),
            }
        }
        thread::sleep(INTERVAL.saturating_sub(tick.elapsed()));
    }
}

fn main() {
    if run().is_err() {
        eprintln!(
            "Agent stopped: check console URL, enrollment token, state permissions and connectivity"
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_proc_socket_addresses() {
        let v4 = if cfg!(target_endian = "little") {
            "0100007F:1F90"
        } else {
            "7F000001:1F90"
        };
        assert_eq!(endpoint(v4, false).unwrap(), "127.0.0.1:8080");
        let v6 = if cfg!(target_endian = "little") {
            "00000000000000000000000001000000:01BB"
        } else {
            "00000000000000000000000000000001:01BB"
        };
        assert_eq!(endpoint(v6, true).unwrap(), "[::1]:443");
        assert!(endpoint("garbage", false).is_err());
    }

    #[test]
    fn converts_proc_memory_to_bytes() {
        assert_eq!(memory_field("VmRSS:\t2048 kB\n", "VmRSS:"), 2097152);
        assert_eq!(memory_field("", "VmRSS:"), 0);
    }
}
