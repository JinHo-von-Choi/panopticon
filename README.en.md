<p align="center"><img src="netwatcher/web/static/img/panopticon.png" alt="Panopticon" width="320" /></p>

# Panopticon

Panopticon monitors network traffic in small offices, labs, and development networks. It helps you identify devices and their connections, investigate port scans and address spoofing, and review unusual traffic with supporting evidence.

Packets and events stay on your own server. Threat feeds, notification channels, and AI analysis are optional.

## Getting started

1. **Choose where to observe traffic.** Connect the sensor to a switch mirror port (SPAN) to observe the intended network segment. An ordinary switch port may expose only the sensor host's traffic and some broadcasts.
2. **Install and check coverage.** Use the dashboard's installation checks to review the interface, storage, and authentication settings.
3. **Investigate an event.** Review the source device, peer, occurrence count, packet evidence, and related events.
4. **Confirm normal activity before tuning.** Record device ownership and expected work. Compare normal and attack samples before approving a detection change.

Start with the [installation guide](docs/INSTALL.md) and [user guide](docs/USER-GUIDE.md). Detailed guides are in Korean; the console supports Korean and English.

## What it provides

| Feature | Purpose |
| --- | --- |
| Device inventory and connection changes | Identify new devices, peers, and unusual connections |
| Detection and related incidents | Investigate spoofing, scans, suspicious internal access, and transfers |
| Repeated-event aggregation | Review representative events and occurrence counts |
| Packet evidence and review pins | Inspect available evidence and retain it during an investigation |
| Confirmed roles and expected traffic | Recognize verified backup and database work |
| Tuning proposals, comparisons, and approval | Review a proposed change before applying it |
| Notifications and operational status | Check delivery, storage failures, queues, and observation gaps |

Press `Ctrl+K` or `Cmd+K` to find a console screen.

## Requirements and limits

- Use Linux with Docker Compose or Python 3.12+, and PostgreSQL. Size storage for the traffic volume and retention period.
- Packet capture requires permission to access the selected interface. Monitor networks you are authorized to manage.
- Panopticon does not decrypt encrypted payloads or assess traffic outside its observation coverage.
- The default supported configuration uses one sensor and one worker. Multi-worker and high-availability deployments are outside that configuration.
- Automatic blocking is disabled by default. A sensor can block only traffic that passes through the path it controls. A SPAN sensor cannot block traffic between other hosts through its local firewall.
- AI provides explanations and proposals. It does not approve configuration changes or operate the firewall.

## Documentation

- [Installation and upgrades](docs/INSTALL.md)
- [Console and investigations](docs/USER-GUIDE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Operations and recovery](docs/OPERATIONS-GUIDE.md)
- [API integration](docs/API.md)
- [Development](docs/DEVELOPMENT.md)
- [Release notes](CHANGELOG.md)
- [Security policy](SECURITY.md)

[한국어](README.md) · [MIT License](LICENSE)
