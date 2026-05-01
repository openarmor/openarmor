<picture>
  <source srcset="assets/OpenArmor_shield_logo_tagline_202605010255.avif" type="image/avif">
  <img src="assets/OpenArmor_shield_logo_tagline_202605010255.avif" alt="OpenArmor — Open Source Endpoint Detection & Response" width="100%">
</picture>

# OpenArmor — Open Source EDR

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![C++](https://img.shields.io/badge/language-C%2B%2B17-00599C.svg)](https://isocpp.org/)
[![GitHub Stars](https://img.shields.io/github/stars/mranv/openarmor?style=social)](https://github.com/mranv/openarmor)
[![Slack](https://img.shields.io/badge/slack-join-4A154B.svg)](https://openedr.com/register/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**OpenArmor** is a full-featured, open source **Endpoint Detection & Response (EDR)** platform for Windows. It monitors your endpoints at kernel level — file system, registry, process, and network — correlates raw telemetry through a declarative policy engine, and ships enriched alerts to ELK or cloud backends. Everything is open: the kernel driver, the agent, the policy language, and the data pipeline.

> Breach detection, protection, and visibility — across every attack vector — without requiring any other agent.

---

## Table of Contents

- [Why OpenArmor](#why-openarmor)
- [Architecture Overview](#architecture-overview)
- [Components](#components)
  - [Kernel Driver (edrdrv)](#kernel-driver-edrdrv)
  - [EDR Service (edrsvc)](#edr-service-edrsvc)
  - [Process Monitor DLL (edrpm)](#process-monitor-dll-edrpm)
  - [System Monitor (libsysmon)](#system-monitor-libsysmon)
  - [Network Monitor (libnetmon)](#network-monitor-libnetmon)
  - [Policy Engine (libedr + edrdata)](#policy-engine-libedr--edrdata)
  - [Cloud Integration (libcloud)](#cloud-integration-libcloud)
  - [Control Utility (edrcon)](#control-utility-edrcon)
- [Data Flow](#data-flow)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Quick Start](#quick-start)
- [Build Instructions](#build-instructions)
- [Installation](#installation)
- [Docker Deployment](#docker-deployment)
- [ELK Stack Integration](#elk-stack-integration)
- [Policy Configuration](#policy-configuration)
- [Telemetry & Cloud](#telemetry--cloud)
- [Screenshots](#screenshots)
- [Community](#community)
- [Contributing](#contributing)
- [License](#license)

---

## Why OpenArmor

<picture>
  <source srcset="assets/Traditional_AV_vs_OpenArmor_EDR_202605010255.avif" type="image/avif">
  <img src="assets/Traditional_AV_vs_OpenArmor_EDR_202605010255.avif" alt="Traditional AV vs OpenArmor EDR comparison" width="100%">
</picture>

Traditional antivirus scans files at rest. OpenArmor watches **behavior in motion** — every process spawn, every registry write, every network connection, every API call — and correlates them into an attack story.

| Capability | Traditional AV | OpenArmor EDR |
|---|---|---|
| File scanning | ✅ | ✅ |
| Real-time process monitoring | ❌ | ✅ |
| Registry change tracking | ❌ | ✅ |
| Network connection analysis | Limited | ✅ |
| API-level hooking | ❌ | ✅ |
| Process hierarchy tracking | ❌ | ✅ |
| MITRE ATT&CK mapping | ❌ | ✅ |
| Open source & auditable | Rarely | ✅ |
| Self-protection | ❌ | ✅ |
| Cloud telemetry pipeline | ❌ | ✅ |
| Declarative policy engine | ❌ | ✅ |

---

## Architecture Overview

<picture>
  <source srcset="assets/Technical_architecture_diagram_l…_202605010255.avif" type="image/avif">
  <img src="assets/Technical_architecture_diagram_l…_202605010255.avif" alt="OpenArmor technical architecture" width="100%">
</picture>

OpenArmor spans two privilege boundaries — kernel mode and user mode — with a structured pipeline between them:

```
╔══════════════════════════════════════════════════════════════════╗
║  KERNEL MODE  (edrdrv.sys)                                       ║
║                                                                  ║
║  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           ║
║  │  FS Minifilter│  │ Proc Monitor │  │  Reg Monitor │           ║
║  │  (filemon)   │  │  (procmon)   │  │  (regmon)    │           ║
║  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           ║
║         │                 │                 │                    ║
║  ┌──────┴─────────────────┴─────────────────┴───────────┐        ║
║  │          Network Monitor  (netmon / WFP)              │        ║
║  └──────────────────────────────────────────────────────┘        ║
║         │         FilterPort (async I/O)                         ║
╚═════════╪════════════════════════════════════════════════════════╝
          │
╔═════════╪════════════════════════════════════════════════════════╗
║  USER MODE                                                       ║
║         ↓                                                        ║
║  ┌──────────────────────────────────────────────────────┐        ║
║  │  libsysmon  ─────  libprocmon  ─────  libnetmon      │        ║
║  │  (FltPortReceiver, 2 worker threads)                 │        ║
║  └──────────────────────┬───────────────────────────────┘        ║
║                         │  IDataReceiver                         ║
║                         ↓                                        ║
║  ┌──────────────────────────────────────────────────────┐        ║
║  │  Event Queue Manager  (named queues per scenario)    │        ║
║  └──────────────────────┬───────────────────────────────┘        ║
║                         │  QSC scenario pipeline                 ║
║                ┌────────┴────────┐                               ║
║          filter_lle         enrich_lle                           ║
║                │                 │                               ║
║          match_patterns     apply_policy                         ║
║                │                 │                               ║
║          get_fls_verdict   check_valkyrie                        ║
║                └────────┬────────┘                               ║
║                         ↓  output.qsc                            ║
║  ┌──────────────────────────────────────────────────────┐        ║
║  │  libcloud  →  AWS Firehose / HTTP / ELK              │        ║
║  └──────────────────────────────────────────────────────┘        ║
╚══════════════════════════════════════════════════════════════════╝
```

**edrpm.dll** is injected into every user-mode process by the kernel driver to provide API-level monitoring from within each process.

---

## Components

### Kernel Driver (edrdrv)

<picture>
  <source srcset="assets/Windows_security_monitoring_laye…_202605010255.avif" type="image/avif">
  <img src="assets/Windows_security_monitoring_laye…_202605010255.avif" alt="Windows kernel monitoring layers" width="100%">
</picture>

The kernel driver (`edrdrv.sys`) is the foundation. It runs at kernel privilege and hooks into Windows internals using Microsoft-approved extension points:

- **File System Minifilter** — intercepts every I/O request to the filesystem (create, write, rename, delete) using the Windows Filter Manager framework. No polling, no scanning; pure real-time event capture.
- **Process Monitor** — tracks process creation and termination using `PsSetCreateProcessNotifyRoutineEx`. Captures command lines, parent PIDs, and image paths at creation time.
- **Registry Monitor** — captures registry reads and writes via `CmRegisterCallback`. Monitors key creation, value modification, and deletion.
- **Network Monitor** — integrates with the Windows Filtering Platform (WFP) via `nfwfpdrv.lib` to monitor inbound/outbound TCP/UDP connections and DNS queries.
- **DLL Injector** — loads `edrpm.dll` into each new user-mode process at creation time, enabling per-process API-level monitoring.
- **Self-Protection** — prevents unauthorized modification of EDR files, registry keys, and process handles.

All kernel events are serialized in LBVS binary format and sent to the user-mode service via a Windows Filter Port (`FltCreateCommunicationPort`) for zero-copy, async delivery.

---

### EDR Service (edrsvc)

The main Windows service (`edrsvc.exe`) is the orchestration layer. It:

- Registers itself as a Windows service with start/stop/restart lifecycle management
- Initializes the global object registry (`ObjectManager`) and service catalog
- Loads configuration from JSON (with command-line overrides)
- Starts all subsystems: `libsysmon`, `libprocmon`, `libnetmon`, `libcloud`
- Owns the event queue manager and routes events through QSC scenario pipelines
- Handles UAC elevation for privileged operations via RPC

The service exposes a control interface via `edrcon` for runtime management.

---

### Process Monitor DLL (edrpm)

<picture>
  <source srcset="assets/Tree_visualization_of_process_hi…_202605010255.avif" type="image/avif">
  <img src="assets/Tree_visualization_of_process_hi…_202605010255.avif" alt="Process hierarchy visualization" width="100%">
</picture>

`edrpm.dll` is injected into every running user-mode process by the kernel driver. Inside each process it uses **Microsoft Detours** to hook Windows API calls:

| API Category | Hooked Functions |
|---|---|
| Clipboard | `GetClipboardData`, `SetClipboardViewer` |
| Keyboard | `GetKeyboardState`, `GetKeyState`, `RegisterHotKey`, `BlockInput`, `KeybdEvent` |
| Mouse | `MouseEvent`, `ClipCursor`, `SendInput` |
| Screen capture | Copy window bitmap APIs |
| Audio | `EnumAudioEndpoints`, `WaveInOpen` |
| Window hooks | `SetWindowsHookEx` (global hooks) |
| Thread impersonation | Impersonation token APIs |
| Disk | Raw volume/disk access |

Events are queued in-process and sent via Filter Port to `libprocmon` in the service. Duplicate events within a configurable timeout window are deduplicated before transmission.

---

### System Monitor (libsysmon)

`libsysmon` owns the Filter Port receiver on the user-mode side. It runs 2 worker threads reading events from the kernel via overlapped async I/O (buffer range 4 KB–1 MB, resized dynamically). Each event is parsed from LBVS binary format into a `Variant` dictionary and handed to the queue manager via `IDataReceiver`.

---

### Network Monitor (libnetmon)

Handles network events from the kernel WFP driver:

| Event | Description |
|---|---|
| `NETMON_CONNECT_OUT` | Outbound TCP/UDP connection established |
| `NETMON_CONNECT_IN` | Inbound connection accepted |
| `NETMON_LISTEN` | Port opened for listening |
| `NETMON_REQUEST_DNS` | DNS query made |
| `NETMON_REQUEST_DATA_HTTP` | HTTP request detected |
| `NETMON_REQUEST_DATA_FTP` | FTP session detected |

<picture>
  <source srcset="assets/Network_traffic_analysis_visuali…_202605010256.avif" type="image/avif">
  <img src="assets/Network_traffic_analysis_visuali…_202605010256.avif" alt="Network traffic analysis" width="100%">
</picture>

---

### Policy Engine (libedr + edrdata)

<picture>
  <source srcset="assets/Policy_engine_visualizing_event_…_202605010255.avif" type="image/avif">
  <img src="assets/Policy_engine_visualizing_event_…_202605010255.avif" alt="Policy engine event processing" width="100%">
</picture>

OpenArmor uses a **declarative pipeline** defined in QSC scenario files (JSON-based). Each event passes through the pipeline in order:

| Stage | File | Purpose |
|---|---|---|
| 1 | `filter_lle.qsc` | Drop noise — filter by base event type and PID |
| 2 | `enrich_lle.qsc` | Walk process hierarchy, attach parent metadata and image path |
| 3 | `match_patterns.qsc` | Apply pattern-matching policies (regex, field conditions) |
| 4 | `apply_policy.qsc` | Evaluate detection rules against enriched events |
| 5 | `get_fls_verdict.qsc` | Query File List Service for file reputation |
| 6 | `check_for_valkyrie.qsc` | Submit unknown files to cloud sandbox |
| 7 | `output.qsc` | Route matched events to cloud or local storage |

The policy definition (`source_policy.json`) supports:

- **Pattern groups** — regex/glob-based matching on paths, command lines, parent chains
- **Event conditions** — field-level comparisons with AND/OR/NOT operators
- **Whitelists/Blacklists** — email paths, registry keys, file extensions, processes
- **MITRE mapping** — each rule can be tagged with ATT&CK tactic/technique IDs

---

### Cloud Integration (libcloud)

<picture>
  <source srcset="assets/Cloud_communication_architecture…_202605010255.avif" type="image/avif">
  <img src="assets/Cloud_communication_architecture…_202605010255.avif" alt="Cloud communication architecture" width="100%">
</picture>

`libcloud` handles bi-directional cloud communication:

**Outbound (telemetry):**
- **AWS Kinesis Data Firehose** — high-throughput event streaming (configured with access key, secret key, delivery stream, region)
- **HTTP REST** — direct API calls for enrollment, heartbeat, and policy fetch

**Inbound (configuration):**
- Heartbeat every 30 seconds (configurable)
- Policy fetch on `PolicyIsUpdated` message
- Cloud config updates propagated via message bus to all subscribers

**Supported protocols:** AWS Firehose, HTTP/HTTPS, FLS v4/v7, GCP

---

### Control Utility (edrcon)

`edrcon.exe` is the command-line management tool:

```
edrcon [mode] [options]

Modes:
  run       Run the EDR service
  debug     Start in debug mode with verbose logging
  dump      Dump current configuration and state
  compile   Compile and validate policy files
  file      File operations (hash, verdict lookup)
  process   Process operations (info, injection status)
  rpcserver Start RPC server for remote control
  unprot    Temporarily disable self-protection (admin)
  wait      Wait for service to reach a specific state
```

---

## Data Flow

End-to-end event lifecycle:

```
1. Kernel event fires (e.g., process creates child process)
   │
2. edrdrv serializes to LBVS binary, sends via FilterPort
   │
3. libsysmon FltPortReceiver receives on async worker thread
   │
4. Event deserialized → Variant dictionary (typed key-value)
   │
5. Pushed to queue manager via IDataReceiver.put()
   │
6. filter_lle.qsc — drop if PID/type not monitored
   │
7. enrich_lle.qsc — attach: parent chain, image path, user SID
                     (ProcessDataProvider cache, 10min TTL)
   │
8. match_patterns.qsc — test against pattern rules
   │                     matched → tag with pattern ID
9. apply_policy.qsc — evaluate detection conditions
   │                   hit → generate alert event
10. get_fls_verdict.qsc — query FLS for file hash reputation
    │
11. check_for_valkyrie.qsc — submit unknown hashes to cloud
    │
12. output.qsc — serialize and route
    │
13. libcloud — batch and ship to AWS Firehose / ELK
```

---

## MITRE ATT&CK Coverage

<picture>
  <source srcset="assets/MITRE_ATT&CK_grid_heatmap_202605010255.avif" type="image/avif">
  <img src="assets/MITRE_ATT&CK_grid_heatmap_202605010255.avif" alt="MITRE ATT&CK coverage heatmap" width="100%">
</picture>

OpenArmor's event collection covers the following MITRE ATT&CK tactics through kernel and API-level monitoring:

| Tactic | Coverage | Key Techniques |
|---|---|---|
| Initial Access | Partial | T1566 Phishing (file drops), T1190 Exploit Public-Facing App |
| Execution | High | T1059 Scripting, T1106 Native API, T1053 Scheduled Tasks |
| Persistence | High | T1547 Boot Autostart, T1060 Registry Run Keys |
| Privilege Escalation | High | T1055 Process Injection, T1134 Access Token Manipulation |
| Defense Evasion | High | T1055 Injection, T1112 Modify Registry, T1562 Impair Defenses |
| Credential Access | High | T1056 Input Capture, T1003 Credential Dumping |
| Discovery | High | T1082 System Info, T1083 File Discovery, T1057 Process Discovery |
| Lateral Movement | Partial | T1021 Remote Services, T1091 Removable Media |
| Collection | High | T1113 Screen Capture, T1115 Clipboard Data, T1123 Audio Capture |
| Exfiltration | High | T1041 Exfil over C2, T1048 Exfil over Alt Protocol |
| Command & Control | High | T1071 App Layer Protocol, T1095 Non-App Layer Protocol |

---

## Quick Start

**Prerequisites:** Windows 10/11 or Windows Server 2016+, Administrator privileges.

### Option 1 — Comodo Dragon Platform (Fastest)

No build required. Email [quick-start@openedr.com](mailto:quick-start@openedr.com) to get an account on the Comodo Dragon platform, which hosts OpenArmor with full telemetry management, no ELK setup needed.

### Option 2 — Self-Hosted with Docker

```bash
git clone https://github.com/mranv/openarmor.git
cd openarmor
docker-compose up -d
```

See [Docker Installation](getting-started/DockerInstallation.md) for full details.

### Option 3 — Native Windows Install

Download the latest installer from [Releases](https://github.com/ComodoSecurity/openedr/releases/tag/release-2.5.1) and follow [Installation Instructions](getting-started/InstallationInstructions.md).

---

## Build Instructions

Building OpenArmor requires the **Windows Driver Kit (WDK)** for the kernel driver component. The agent builds with Visual Studio 2017 or 2019.

### Prerequisites

- Visual Studio 2017 or 2019 (C++ Desktop workload)
- Windows Driver Kit (WDK) matching your VS version
- Windows SDK 10.0.18362 or later
- Git with LFS support

### Clone

```bash
git clone --recursive https://github.com/mranv/openarmor.git
cd openarmor
```

### Build (VS2019)

Open `edrav2/build/vs2019/edrav2.sln` in Visual Studio, select the target configuration (Debug/Release × x64), and build the solution.

Or from command line using the build pipeline:

```cmd
cd edrav2\build\buildpipe
builder.cmd Release x64
```

For detailed instructions including dependency setup: [Build Instructions](getting-started/BuildInstructions.md).

---

## Installation

<picture>
  <source srcset="assets/Windows_installer_wizard_splash_…_202605010255.avif" type="image/avif">
  <img src="assets/Windows_installer_wizard_splash_…_202605010255.avif" alt="OpenArmor installer wizard" width="100%">
</picture>

Full step-by-step guide: [Installation Instructions](getting-started/InstallationInstructions.md)

**Key steps:**

1. Run the MSI installer as Administrator
2. The installer deploys `edrdrv.sys` (signed kernel driver), `edrsvc.exe`, and `edrpm.dll`
3. The service auto-starts on boot
4. Configure your cloud or ELK endpoint in `edrsvc.json`
5. Verify with `edrcon dump` — should show all subsystems running

---

## Docker Deployment

<picture>
  <source srcset="assets/OpenArmor_deployment_network_dia…_202605010256.avif" type="image/avif">
  <img src="assets/OpenArmor_deployment_network_dia…_202605010256.avif" alt="OpenArmor deployment topology" width="100%">
</picture>

Docker simplifies deploying the ELK backend (Elasticsearch, Logstash, Kibana) that receives OpenArmor telemetry:

```bash
# Start the full ELK stack
docker-compose up -d

# Verify containers
docker ps
```

![Docker compose up](docs/screenshots/docker-compose-allup.avif)
![Docker ps](docs/screenshots/docker-ps-list.avif)

See [Docker Installation](getting-started/DockerInstallation.md) for network configuration, volume mounts, and production hardening.

---

## ELK Stack Integration

<picture>
  <source srcset="assets/Data_pipeline_flow_diagram_202605010255.avif" type="image/avif">
  <img src="assets/Data_pipeline_flow_diagram_202605010255.avif" alt="ELK data pipeline" width="100%">
</picture>

OpenArmor ships telemetry via **Filebeat → Logstash → Elasticsearch → Kibana**:

```
[Windows Endpoint]
  OpenArmor Agent
       ↓ writes events to log file
  Filebeat
       ↓ ships to
  Logstash (parsing + enrichment)
       ↓ indexes to
  Elasticsearch
       ↓ visualized in
  Kibana
```

### Setup Guides

1. [Setting up ELK](getting-started/SettingELK.md) — Elasticsearch, Logstash, Kibana
2. [Setting up Filebeat](getting-started/SettingFileBeat.md) — agent-side shipper
3. [Setting up Kibana](getting-started/SettingKibana.md) — dashboards and search

### Filebeat Screenshots

| Step | Screenshot |
|---|---|
| Install Filebeat | ![](docs/screenshots/installing%20filebeat1.avif) |
| Install Filebeat 2 | ![](docs/screenshots/installing%20file%20beat2.avif) |
| Enable module | ![](docs/screenshots/filebeat-enable-module-logstash.avif) |
| Configure inputs | ![](docs/screenshots/filebeatinputs-filebeatyaml.avif) |
| Configure modules | ![](docs/screenshots/filebeatmodules-filebeatyaml.avif) |
| Logstash config | ![](docs/screenshots/logstashconfig-filebeatyml.avif) |
| Logstash yaml | ![](docs/screenshots/logstash-yaml.avif) |
| Restart service | ![](docs/screenshots/services-filebeat-restart.avif) |
| Git clone ELK | ![](docs/screenshots/git-clone-elk.avif) |

---

## Policy Configuration

<picture>
  <source srcset="assets/Security_alert_OpenArmor_threat_…_202605010256.avif" type="image/avif">
  <img src="assets/Security_alert_OpenArmor_threat_…_202605010256.avif" alt="OpenArmor threat alert" width="100%">
</picture>

Policies control what OpenArmor detects and alerts on. See [Editing Alerting Policies](getting-started/EditingAlertingPolicies.md).

Policies live in `edrav2/iprj/edrdata/` as JSON:

```json
{
  "patterns": {
    "powershell_obfuscated": {
      "match": {
        "imageFile": ".*\\\\powershell\\.exe",
        "cmdLine": ".*-[Ee][Nn][Cc].*|.*[Ee]ncodedCommand.*"
      }
    }
  },
  "events": {
    "suspicious_powershell": {
      "baseType": "LLE_PROCESS_CREATE",
      "conditions": ["powershell_obfuscated"],
      "mitre": { "tactic": "Execution", "technique": "T1059.001" },
      "severity": "high"
    }
  }
}
```

**Policy operators:** `match` (regex), `equals`, `contains`, `startsWith`, `endsWith`, `in`, `not`, `and`, `or`

**Policy groups:**
- `PatternsMatching` — path and string pattern rules
- `EventsMatching` — full event condition chains

---

## Telemetry & Cloud

OpenArmor sends enriched events to your configured backend:

### AWS Kinesis Data Firehose

```json
{
  "cloud": {
    "provider": "aws",
    "firehose": {
      "accessKeyId": "YOUR_ACCESS_KEY",
      "secretAccessKey": "YOUR_SECRET_KEY",
      "deliveryStream": "openarmor-events",
      "region": "us-east-1"
    }
  }
}
```

### Self-Hosted ELK

```json
{
  "cloud": {
    "provider": "elk",
    "elasticsearch": {
      "endpoint": "http://your-elk-host:9200",
      "index": "openarmor-events"
    }
  }
}
```

Each event includes: timestamp, endpoint ID, process hierarchy, file hashes (SHA256/MD5/xxHash), user SID, network context, and MITRE tags.

---

## Screenshots

<picture>
  <source srcset="assets/Cybersecurity_analyst_dashboard_…_202605010256.avif" type="image/avif">
  <img src="assets/Cybersecurity_analyst_dashboard_…_202605010256.avif" alt="Cybersecurity analyst dashboard" width="100%">
</picture>

### Detection & Alerting
![Detection and Alerting](docs/screenshots/Screenshot_1.avif)

### Event Details
![Event Details](docs/screenshots/Screenshot_2.avif)

### Dashboard
![Dashboard](docs/screenshots/Screenshot_3.avif)

### Process Timeline
![Process Timeline](docs/screenshots/Screenshot_4.avif)

### Process Tree View
![Process Tree View](docs/screenshots/Screenshot_5.avif)

### Event Search
![Event Search](docs/screenshots/Screenshot_6.avif)

### Kibana — Elasticsearch UI
![Elastic UI 1](docs/screenshots/elastic%20ui1.avif)
![Elastic UI 2](docs/screenshots/elastic%20ui2.avif)
![Elastic UI 3](docs/screenshots/elastic%20ui3.avif)
![Elastic UI 4](docs/screenshots/elastic%20ui4.avif)
![Elastic UI 5](docs/screenshots/elastic%20ui5.avif)
![Elastic UI 6](docs/screenshots/elastic%20ui6.avif)
![Elastic UI 7](docs/screenshots/elastic%20ui7.avif)

---

## File Integrity Monitoring

<picture>
  <source srcset="assets/File_integrity_monitoring_visual…_202605010256.avif" type="image/avif">
  <img src="assets/File_integrity_monitoring_visual…_202605010256.avif" alt="File integrity monitoring visualization" width="100%">
</picture>

The filesystem minifilter captures every file operation in real time. For each event OpenArmor records:

- File path (device path resolved to volume path)
- Operation type (create, write, rename, delete, read)
- Process that performed the operation
- File hash (SHA256 computed on modification)
- Code signing status (publisher, signature valid/invalid)
- FLS reputation verdict (clean/malicious/unknown)

Hashes are cached to avoid redundant computation. The `FileDataProvider` in `libsyswin` maintains a hash cache with configurable TTL.

---

## Self-Protection

<picture>
  <source srcset="assets/Armor_defending_against_laser_beams_202605010255.avif" type="image/avif">
  <img src="assets/Armor_defending_against_laser_beams_202605010255.avif" alt="Self-protection — EDR defending against attacks" width="100%">
</picture>

OpenArmor protects itself from tampering:

- **Driver protection** — `edrdrv.sys` cannot be unloaded by non-system processes
- **File protection** — EDR binaries and configuration files are write-protected from user space
- **Registry protection** — service registry keys cannot be modified without elevated authorization
- **Process protection** — EDR service process handle is restricted; external processes cannot terminate it

The `unprot` mode in `edrcon` temporarily disables self-protection for authorized maintenance (requires admin and logs the event).

---

## Community

<picture>
  <source srcset="assets/Diverse_developers_collaborating…_202605010255.avif" type="image/avif">
  <img src="assets/Diverse_developers_collaborating…_202605010255.avif" alt="Open source community collaborating" width="100%">
</picture>

- **Slack:** [openedr.com/register](https://openedr.com/register/)
- **Community Forums:** [community.openedr.com](https://community.openedr.com/)
- **Email:** [register@openedr.com](mailto:register@openedr.com)
- **Issues:** [GitHub Issues](https://github.com/mranv/openarmor/issues)
- **Roadmap:** [GitHub Projects](https://github.com/ComodoSecurity/openedr_roadmap/projects/1)

---

## Contributing

We welcome contributions of all kinds — bug fixes, new detection rules, documentation, and drivers for new platforms.

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development environment setup
- Code style and conventions
- How to submit a pull request
- How to write and test policies
- Kernel driver signing requirements

---

## License

OpenArmor is released under the [MIT License](LICENSE.md).

---

<div align="center">

<picture>
  <source srcset="assets/Cybersecurity_shield_logo_OpenArmor_202605010313.avif" type="image/avif">
  <img src="assets/Cybersecurity_shield_logo_OpenArmor_202605010313.avif" alt="OpenArmor shield" width="200">
</picture>

**OpenArmor** — Open Source Endpoint Detection & Response

*Built by the community. For the community.*

</div>
