<p align="center"><img src="netwatcher/web/static/img/panopticon.png" alt="Panopticon" width="320" /></p>

# Panopticon

Panopticon is a console for investigating security alerts in small offices, labs, and development networks. It reads existing Suricata EVE logs, groups repeated alerts, and brings device roles, work schedules, and communication evidence into the investigation.

Review whether a transfer matches a backup job or involves an unfamiliar peer, then record the evidence behind your decision. Investigation records stay in PostgreSQL on your own server. AI analysis and notifications are optional.

## Getting started

1. **Connect Suricata logs.** Install using a readable `eve.json` file. The default installation needs no packet capture privileges.
2. **Check collection and retention.** Review input connectivity, storage failures, possible gaps, and retention capacity.
3. **Investigate priority cases.** Open a representative event and compare previous alerts, the source device, its peer, and original evidence.
4. **Record decisions and handoffs.** Assign an owner and document the evidence, scope, and expiry of a normal-activity review. Revisit it when conditions change.

Start with the [installation guide](docs/INSTALL.md) and [user guide](docs/USER-GUIDE.md). Detailed guides are in Korean; the console supports Korean and English.

## What it provides

| Feature | Purpose |
| --- | --- |
| Repeated alerts and previous cases | Compare representative events while retaining individual originals |
| Device roles and work schedules | Record ownership, expected communication, and planned jobs |
| Decisions and collaboration | Track assignees, case status, handoff notes, and review history with separate admin, analyst, and viewer permissions |
| Evidence retention | Inspect original alerts and investigation evidence; retained packets are available in direct capture deployments |
| Tuning proposals and approval | Compare normal and attack samples before an administrator approves a change in a supported sensor deployment |
| Lightweight host agent | Collect Linux TCP sockets, load and memory with a Rust executable; the local release build is about 1.6 MiB. A systemd installer and HMAC-SHA256 gateway support consecutive event sequences and idempotent retries. See [agent installation](docs/INSTALL.md#호스트-에이전트-설치) |
| Tenant isolation foundation | PostgreSQL RLS and transaction tenant contexts cover `events`, `devices`, `incidents` and `audit_log`; HTTP tenant selection and isolation of all project data require further integration |
| Hash-chained audit trail | SHA-256 `prev_hash` and `entry_hash` fields with `verify_chain(tenant_id)` detect content/link mismatches and identify the first broken row. See [verification scope](docs/API.md#감사-로그-무결성과-테넌트-컨텍스트) |
| Cybernetic console | Operator, Auditor and Cinematic themes; Canvas2D topology; NIST CSF / PCI DSS coverage and KPIs; a tactic-grouped MITRE ATT&CK frequency heatmap with Navigator Layer JSON export |

Press `Ctrl+K` or `Cmd+K` to find a console screen.

## Requirements and limits

- Use Linux with Docker Compose or Python 3.12+, and PostgreSQL. Size storage for the traffic volume and retention period.
- The default EVE deployment investigates alerts recorded by Suricata. It does not invent missing packet evidence or infer verified device ownership.
- Direct capture requires a separate sensor, SPAN or TAP access, and capture privileges. The web console runs without capture privileges. See [direct capture installation](docs/INSTALL.md#직접-패킷을-캡처하기).
- Panopticon does not decrypt HTTPS payloads or assess traffic outside its coverage. Capacity depends on the input, ruleset, and hardware.
- The default direct capture configuration uses one sensor and one worker. Multi-worker and high-availability deployments are outside that configuration.
- The default installation is for read-only investigation. A normal-activity review does not automatically create detection exceptions or change the firewall. AI does not approve configuration changes.

## Documentation

- [Installation and upgrades](docs/INSTALL.md)
- [Release verification](docs/RELEASE-VERIFICATION.md)
- [Console and investigations](docs/USER-GUIDE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Operations and recovery](docs/OPERATIONS-GUIDE.md)
- [API integration](docs/API.md)
- [Development](docs/DEVELOPMENT.md)
- [Release notes](CHANGELOG.md)
- [Security policy](SECURITY.md)

[한국어](README.md) · [MIT License](LICENSE)
