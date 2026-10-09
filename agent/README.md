# Panopticon host agent

Linux `/proc/net/tcp` and `/proc/net/tcp6` collector. Sends signed heartbeat and
connection state changes every five seconds. Rustls verifies HTTPS certificates;
HTTP is allowed only for loopback development consoles. Connection sampling is
limited to 256 entries per interval. Listening sockets are excluded.

```sh
cargo build --release --manifest-path agent/Cargo.toml
```

The executable is `agent/target/release/panopticon-agent`. It needs no Rust runtime.
The release profile minimizes size. Binary size and idle RSS target: below 15 MiB.

## Gateway

Set `PANOPTICON_ENROLLMENT_TOKEN` in the console environment before startup. Each
token expires 15 minutes after the gateway first sees it and can enroll one host.
Restarting the console does not renew or reset a consumed token. Use a fresh token
and restart the console for each new enrollment. Enrollment credentials are returned
once; keep the agent state directory intact.

`agent_gateway.database` selects the console's SQLite file, default
`data/agent-gateway.sqlite3`. The file stores agent identities, resource snapshots
and received event batches, with mode 0600. Use a console-owned directory and
retain this file across restarts. No agent data is inserted into the existing
alert pipeline by this foundation gateway.

`POST /api/agent/enroll` accepts `enrollment_token`, `hostname`, `platform` and
returns `agent_uuid`, `auth_token`, `signing_key`, `heartbeat_interval_seconds`.
Heartbeat and events require `Authorization: Bearer <auth_token>`, `X-Agent-UUID`,
`X-Agent-Timestamp` (Unix seconds, maximum clock skew 60 seconds), and
`X-Agent-Signature` (hex HMAC-SHA256). HMAC input is timestamp, newline, then the
exact request bytes; its key is decoded from the enrollment's hex signing key.
These credentials do not grant dashboard access.

Heartbeat payload: `agent_uuid`, `latency_ms` (previous successful heartbeat RTT),
`resources` (`load_1`, `memory_total_bytes`, `memory_available_bytes`,
`agent_rss_bytes`). Gateway receipt time determines `last_seen`.

Events payload: `agent_uuid`, `seq` (starts at 1), `events` (1–256 entries).
Each event includes `kind` (`connection` or `anomaly`), `local_address`,
`remote_address`, `state`, `inode`, `observed_at`; `detail` is optional.
Sequences must be consecutive. Identical retries return `duplicate: true`;
conflicting or skipped sequences return HTTP 409.

## Install

Run as root with these environment variables:

- `PANOPTICON_CONSOLE_URL`: console origin, for example `https://console.example`.
- `PANOPTICON_ENROLLMENT_TOKEN`: fresh URL-safe enrollment token.
- `PANOPTICON_AGENT_BINARY_URL`: HTTPS artifact URL for the host architecture.
- `PANOPTICON_AGENT_SHA256`: artifact checksum obtained through a trusted channel.

Then run `bash scripts/agent/install.sh`. For local builds, set
`PANOPTICON_AGENT_BINARY` to the executable path instead of the download variables.
For a hosted installer, the same environment can be supplied to
`curl -fsSL https://<artifact-host>/install.sh | bash` in a root shell.
No artifact hosting endpoint is supplied by this repository.

The installer supports x86_64/aarch64 and installs a systemd service with a dynamic
user, a private state directory and `MemoryHigh=15M`. Credentials are injected via
`/etc/panopticon-agent/agent.env` (0600). Check `systemctl status panopticon-agent`
and `journalctl -u panopticon-agent` after installation.

Identity, sequence and one pending event batch are atomically persisted with
fsync in `PANOPTICON_STATE_DIR` (default `/var/lib/panopticon-agent`). An exclusive
process lock prevents two agents using the same identity concurrently. Retries
retain the exact pending batch and sequence. Sampling pauses while that batch is
pending; this is not a full offline history buffer.

This foundation uses polling and HTTPS plus HMAC. Netlink/eBPF, full disk WAL,
mTLS certificate issuance/renewal, silent-agent alerts and multi-tenant PostgreSQL
RLS remain separate stages. It does not satisfy the plan's 30-minute zero-loss
acceptance condition.
