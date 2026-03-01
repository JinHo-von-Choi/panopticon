<p align="center">
  <img src="netwatcher/web/static/img/panopticon.png" alt="Panopticon" width="360" />
</p>

<p align="center">
  <strong>Local Network Packet Monitoring and Real-time Threat Detection System</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=white" alt="Python 3.12+" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Scapy-2.6-blue" alt="Scapy" />
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License" />
  <img src="https://img.shields.io/badge/tests-934%20passed-brightgreen" alt="Tests" />
</p>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Network Visibility Requirements](#network-visibility-requirements)
- [Detection Engine Details](#detection-engine-details)
- [NetFlow-based Detection Engines](#netflow-based-detection-engines)
- [Web Dashboard](#web-dashboard)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [Configuration Guide](#configuration-guide)
- [Docker Deployment](#docker-deployment)
- [Operational Considerations](#operational-considerations)
- [External Data Dependencies](#external-data-dependencies)
- [API Reference](#api-reference)
- [Extension Guide](#extension-guide)
- [Tech Stack & Code Quality](#tech-stack--code-quality)

---

## Overview

**Panopticon** is an all-in-one network security monitoring system designed for small to medium-sized network environments. It provides everything needed for network security monitoring in a single package—from Scapy-based real-time packet capture to 18 packet-based detection engines, 2 NetFlow-based detection engines, Kill Chain-based incident correlation, automated IP blocking (IRS), threat intelligence feed integration, AI-driven false positive reduction (AIAnalyzer), and a real-time web dashboard.

### Motivation

Office development networks are often isolated via VPCs and VPNs. However, within the same segment, there are often users who maintain cluttered desktops and plug in USB drives that might carry malware. While firewalls protect the perimeter, internal movements often go unchecked. This project was born from that security concern.

### Core Design Philosophy

| Principle | Description |
|-----------|-------------|
| **Single Deployment** | Handles capture, detection, notification, and dashboard in a single Python process. No separate message queues or distributed systems required. |
| **Plugin Architecture** | Detection engines are automatically discovered and registered by inheriting from the `DetectionEngine` base class. |
| **Runtime Configuration** | Parameters for all engines can be modified in real-time via the Web UI, with YAML persistence and hot-reloading. |
| **Defense in Depth** | 4-layer detection (Packet, Protocol, Behavior, Threat Intel) ensures that if one engine is bypassed, others can still catch the threat. |
| **Zero-Dependency Detection** | Behavior-based detection operates independently without requiring external signature DBs or cloud connectivity. |

---

## Key Features

### Real-time Packet Analysis

- Lossless packet capture via Scapy `AsyncSniffer` (promiscuous mode).
- BPF filter support to limit capture scope.
- Thread-safe asyncio bridge: Capture Thread -> Event Loop -> Detection Engines.
- Per-packet OS fingerprinting (based on TTL/Window Size) and automatic MAC vendor identification.
- Asynchronous reverse DNS lookups (LRU cache of 4,096 entries).

### 18 Packet-based + 2 NetFlow-based Detection Engines

Covers the entire spectrum of network security, including packet layers (L2~L7), statistical anomalies, behavioral profiles, threat intelligence, and custom signatures. Each engine can be independently toggled and tuned. In environments without SPAN, NetFlow-based engines (`flow_port_scan`, `flow_data_exfil`) supplement visibility at the router level.

### Kill Chain Incident Correlation

Automatically constructs attack scenarios by linking individual alerts chronologically. Maps events to a 6-stage Kill Chain: Reconnaissance -> Initial Access -> Command & Control (C2) -> Lateral Movement -> Defense Evasion -> Data Exfiltration.

### Automated Response System (IRS)

Automatically blocks attacking IPs via `iptables` or `nftables` when a threat is detected. Supports whitelisting, maximum block limits, and configurable block durations with automatic expiration.

### Threat Intelligence Integration

Periodically downloads external threat feeds (IP/Domain/JA3 blocklists) and cross-validates them against real-time traffic. Custom blocklists can be managed through the Web UI.

### Real-time Web Dashboard

Provides a single-page dashboard integrating Chart.js-based traffic visualization, WebSocket real-time event streaming, device management, engine configuration, and blocklist/whitelist management. The frontend is built with ES modules and supports Korean/English i18n.

### Multi-channel Notifications

Supports immediate notifications via Slack, Telegram, and Discord webhooks, as well as daily security reports. Prevents alert fatigue using sliding-window rate limiting.

### AI-powered False Positive Reduction (AIAnalyzer)

Periodically analyzes recent CRITICAL/WARNING events using AI CLI (GitHub Copilot / Claude / Gemini / etc.) in batches to automate false positive handling.

- **CONFIRMED_THREAT**: Resends notification if confirmed as a real threat (bypasses rate limit).
- **FALSE_POSITIVE**: Automatically increases the engine's threshold and triggers a hot-reload.
- **MISSED_THREAT**: Identifies real threats missed by engines in INFO events, upgrades them to CRITICAL, and lowers thresholds.
- **UNCERTAIN**: Logs the reasoning when a determination cannot be made.

AI reasoning is stored in the event database and can be reviewed in the **AI Analyzer** tab.
Supported AI Providers: `copilot` (default), `claude`, `codex`, `gemini`, `agent`.

### Prometheus Metrics

Exposes operational metrics such as packet processing rate, alert generation count, webhook latency, DB query performance, and per-engine analysis time via the `/metrics` endpoint.

---

## System Architecture

```
                                    ┌─────────────────────────────────────┐
                                    │         Panopticon Dashboard        │
                                    │    (FastAPI + WebSocket + Chart.js) │
                                    └──────────────┬──────────────────────┘
                                                   │ REST API / WebSocket
                                                   │
┌──────────────┐    call_soon_threadsafe    ┌───────┴───────┐
│    Scapy     │ ────────────────────────> │  PacketProcessor│
│ AsyncSniffer │   Thread-safe Bridge       │  (Event Loop)   │
│ (Capture Th) │                           └───────┬───────┘
└──────────────┘                                   │
                                      ┌────────────┼────────────┐
                                      │            │            │
                                      v            v            v
                              ┌──────────┐ ┌────────────┐ ┌──────────┐
                              │  Engine  │ │   Engine   │ │  Engine  │
                              │ Registry │ │  Registry  │ │ Registry │
                              │ (18 units) │ │ (18 units) │ │ (18 units) │
                              └────┬─────┘ └─────┬──────┘ └────┬─────┘
                                   │             │             │
                                   └─────────────┼─────────────┘
                                                 │ Alert
                                                 v
                              ┌──────────────────────────────────┐
                              │        AlertDispatcher           │
                              │  Rate Limit → DB → WebSocket →  │
                              │  Correlator → Webhooks → IRS    │
                              └──────────┬───────────────────────┘
                                         │
                          ┌──────────────┼──────────────┐
                          v              v              v
                    ┌──────────┐  ┌──────────┐  ┌──────────┐
                    │PostgreSQL│  │  Slack/   │  │ iptables │
                    │ (Storage)│  │ Telegram/ │  │ /nftables│
                    │          │  │ Discord   │  │ (Block)  │
                    └──────────┘  └──────────┘  └──────────┘
```

### Packet Processing Pipeline

1. **Capture**: Scapy `AsyncSniffer` captures raw packets in a background thread.
2. **Bridge**: Packets are passed to the asyncio event loop via `call_soon_threadsafe`.
3. **Analysis**: `PacketProcessor` extracts info and calls the `analyze()` method of all active engines via the `EngineRegistry`.
4. **Dispatch**: Detected `Alert` objects are handled by the `AlertDispatcher`: Rate Limiting -> DB Persistence -> Logging -> WebSocket Broadcast -> Webhook Transmission.
5. **Correlation**: `AlertCorrelator` maps related alerts to Kill Chain stages to create or update Incidents.
6. **Response**: If IRS is enabled, automated IP blocking is performed based on the detection results.

### Background Services

| Service | Interval | Role |
|---------|----------|------|
| `TickService` | 1s | Calls engine `on_tick()` (for window-based detection), Sniffer watchdog. |
| `StatsFlushService` | 60s | Batch flushes traffic counters/device buffers to DB, updates Prometheus metrics. |
| `MaintenanceService` | 6h | Applies data retention policies, refreshes threat feeds, cleans up expired blocks. |
| `AIAnalyzerService` | Configurable (15m default) | Batch analyzes recent events via AI -> Auto-adjusts thresholds, re-alerts real threats, upgrades missed threats to CRITICAL. |

---

## Network Visibility Requirements

> **Core Premise**: Panopticon is a tool for analyzing traffic. Traffic must reach its NIC to be analyzed.
> Without SPAN/Port Mirroring, unicast traffic isolated by a switch will never be seen.

### Issues with Lack of Visibility

Installing Panopticon in an environment with a standard consumer router and unmanaged switch results in:

- **What is visible**: Own traffic, ARP broadcasts, DHCP, Multicast.
- **What is NOT visible**: Any unicast traffic between other hosts.

Consequently, only 3 out of 18 detection engines (ARP/DHCP/MAC Spoofing) will function effectively. The remaining 15 engines will stay dormant as packets never reach them.

### Deployment Topology Options

#### Option 1: Managed Switch SPAN (Recommended)

```
Internet
  │
[Router]
  │
[Managed Switch] ─── SPAN Mirror Port ───> [Panopticon Host]
  ├── Host A
  ├── Host B
  └── Host C
```

| Item | Details |
|------|---------|
| Pros | No impact on network performance, no inline equipment required. |
| Cons | Requires a managed switch (Cisco, Netgear, TP-Link, MikroTik, etc.). |
| Note | Consumer unmanaged switches do not support port mirroring. |

#### Option 2: Direct Installation on Router/Firewall

```
Internet
  │
[OpenWrt / pfSense / MikroTik Router] ← Install Panopticon directly
  │
[Switch]
  ├── Host A
  └── Host B
```

| Item | Details |
|------|---------|
| Pros | Captures all traffic at the router level, no extra hardware needed. |
| Cons | Shares Router CPU, requires custom firmware (OpenWrt, pfSense, etc.). |

#### Option 3: Raspberry Pi Inline Tap (Alternative for Unmanaged Switches)

```
Internet
  │
[Router]
  │
[Raspberry Pi — eth0 ↔ br0 ↔ eth1] ← Panopticon captures on br0
  │
[Unmanaged Switch]
  ├── Host A
  └── Host B
```

| Item | Details |
|------|---------|
| Pros | Full visibility even with unmanaged switches, low cost (~$100). |
| Cons | Inline configuration—Pi failure leads to network segment disconnection. |
| Limit | Pi 4B supports up to ~300Mbps practically (cannot handle full GbE). |

### Visibility Level Check

The **Hosts Visible** card on the dashboard indicates the visibility level in real-time based on the number of unique source MACs observed in the last 60 seconds.

| Level | Unique Source MACs | Meaning |
|-------|--------------------|---------|
| `none` | 1 ~ 2 | SPAN not configured. Only ARP/DHCP detection works. |
| `partial` | 3 ~ 8 | Only partial traffic visible. Check topology. |
| `full` | 9+ | SPAN working correctly. Full detection active. |

---

## Detection Engine Details

### Layer 2 — Data Link Layer

- **ARP Spoof (`arp_spoof`)**: Detects ARP cache poisoning and Gratuitous ARP bursts.
- **DHCP Spoof (`dhcp_spoof`)**: Detects unauthorized DHCP servers and DHCP Starvation attacks.
- **MAC Spoof (`mac_spoof`)**: Detects MAC cloning and spoofing (Locally Administered Bits).

### Layer 3~4 — Network/Transport Layer

- **Port Scan (`port_scan`)**: Classifies and detects TCP SYN/FIN/NULL/XMAS/ACK scans.
- **ICMP Anomaly (`icmp_anomaly`)**: Detects Ping Sweeps, ICMP Floods, and suspicious ICMP types.
- **Protocol Anomaly (`protocol_anomaly`)**: Detects TTL tampering, abnormal TCP flags, and IP spoofing indicators.
- **Lateral Movement (`lateral_movement`)**: Tracks access to sensitive ports (SSH, RDP, SMB) and detects pivot chains.
- **Ransomware Lateral (`ransomware_lateral`)**: Detects SMB/RDP brute force patterns and Honeypot access.

### Layer 7 — Application Layer

- **DNS Anomaly (`dns_anomaly`)**: Detects DGA domains, DNS tunneling, and query volume anomalies.
- **DNS Response (`dns_response`)**: Detects Fast-flux botnets and DGA NXDOMAIN bursts.
- **HTTP Suspicious (`http_suspicious`)**: Identifies security scanners and detects C2 beacon patterns via periodicity analysis.
- **Protocol Inspect (`protocol_inspect`)**: Deep Packet Inspection (DPI) for HTTP, SMTP, FTP, and SSH.

### TLS/Encryption Analysis

- **TLS Fingerprint (`tls_fingerprint`)**: Analyzes JA3/JA4/JA3S fingerprints, SNI, and certificate anomalies (expiry, self-signed).

### Statistical/Behavioral Detection

- **Traffic Anomaly (`traffic_anomaly`)**: Detects volume anomalies using Z-scores and monitors new device arrivals.
- **Behavior Profile (`behavior_profile`)**: Learns baselines for 6 dimensions (Bytes, Packets, Unique IPs/Ports, etc.) and detects deviations.
- **Data Exfiltration (`data_exfil`)**: Detects large outbound transfers and DNS-based exfiltration.

---

## Web Dashboard

### Visibility Level (Hosts Visible)
The dashboard displays visibility as `none` / `partial` / `full` based on unique MACs observed.

### Tabs

| Tab | Description |
|-----|-------------|
| **Events** | Detected event list with severity/engine/date/keyword filters, pagination, CSV/JSON export |
| **Traffic** | Packets-per-minute timeline, protocol distribution pie chart, severity/engine alert charts |
| **Devices** | Network device list (MAC, IP, vendor, OS, packet count), device registration and editing |
| **Blocklist** | Custom IP/domain blocklist management, threat feed statistics |
| **Whitelist** | Allowlist management — add/remove IP, MAC, domain, IP Range entries; type filter and search. Whitelist entries are included in the AI analysis prompt to improve false positive detection |
| **Engines** | Enable/disable toggle and real-time parameter editing for 18 detection engines |
| **AI Analyzer** | AI false positive analysis history (verdict filter, threshold adjustment history), service status. Tab is only shown when `ai_analyzer.enabled: true` |

---

## Quick Start

### Prerequisites
- Python 3.12+
- PostgreSQL 16+ (or Docker)
- libpcap (for packet capture)
- root privileges (for raw socket access)

### Local Installation
```bash
# 1. Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Setup environment
cp .env.example .env
# Edit .env with DB credentials and JWT secret

# 3. DB Migrations
python -m alembic upgrade head

# 4. Run (Requires root)
sudo .venv/bin/python -m netwatcher
```

### Docker Deployment
```bash
# 1. Setup environment
cp .env.example .env

# 2. Build and run (Including PostgreSQL)
docker compose --profile db up -d

# 3. DB Migrations
docker compose --profile migrate run --rm db-migrate
```

---

## Configuration Guide

All configurations are managed in `config/default.yaml`. Sensitive info can be overridden by environment variables.

- **Capture**: Define `interface` and `bpf_filter`.
- **NetFlow**: Enable `netflow.enabled: true` to receive NetFlow v5 on UDP 2055.
- **AI Analyzer**: Enable `ai_analyzer.enabled: true` and select a provider (`copilot`, `claude`, etc.).
- **IRS (Response)**: Enable `response.enabled` to activate automated IP blocking via `iptables`/`nftables`.

---

## Operational Considerations

### Performance Guidelines
- **Small Home/Office (< 50 devices)**: 2 cores, 4 GB RAM.
- **Medium Network (50~200 devices)**: 4 cores, 8 GB RAM.
- **High Traffic (> 500 Mbps)**: 8 cores, 16 GB RAM. Consider selective engine deactivation.

### Gradual IRS Activation
Automated blocking can lead to service disruptions. We strongly recommend:
1. **Observation (1-2 weeks)**: Run with `response.enabled: false`.
2. **Whitelist Configuration**: Add internal servers and critical IPs to `response.whitelist`.
3. **Pilot Engine**: Enable only for `threat_intel` first.
4. **Full Activation**: Gradually add `port_scan`, `arp_spoof`, etc.

---

## External Data Dependencies

### Threat Intelligence Feeds
Integrated with open-source feeds from **Abuse.ch** (URLhaus, Feodo Tracker, SSLBL, ThreatFox), **OpenPhish**, **Emerging Threats**, and **Blocklist.de**.

---

## API Reference
All APIs require JWT Authentication (`Authorization: Bearer <token>`).
- `/api/events`: Event retrieval and export.
- `/api/devices`: Device inventory management.
- `/api/engines`: Runtime configuration for detection engines.
- `/api/blocklist`: Management of threat intel and custom blocks.
- `/api/ai-analyzer/status`: Current status of the AI analyzer.

---

## Tech Stack & Code Quality

- **Packet Capture**: Scapy 2.6
- **Web Framework**: FastAPI 0.115 + Uvicorn
- **Database**: PostgreSQL 16 + asyncpg
- **Migrations**: Alembic
- **AI Integration**: Custom bridges for various AI CLIs.
- **Testing**: Over 900 tests covering unit, integration, and performance layers.

---

## License
MIT License

---

<p align="center">
  <sub>Crafted for network defenders who believe in seeing everything.</sub>
</p>

---

<p align="center">
  Made by <a href="mailto:jinho.von.choi@nerdvana.kr">Jinho Choi</a> &nbsp;|&nbsp;
  <a href="https://buymeacoffee.com/jinho.von.choi">Buy me a coffee</a>
</p>
