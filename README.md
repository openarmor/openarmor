<picture>
  <source srcset="assets/OpenArmor_shield_logo_tagline_202605010255.avif" type="image/avif">
  <img src="assets/OpenArmor_shield_logo_tagline_202605010255.avif" alt="OpenArmor — Open Source Endpoint Detection & Response" width="100%">
</picture>

# OpenArmor — Open Source EDR

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![C++](https://img.shields.io/badge/language-C%2B%2B17-00599C.svg)](https://isocpp.org/)
[![GitHub Stars](https://img.shields.io/github/stars/openarmor/openarmor?style=social)](https://github.com/openarmor/openarmor)
[![Slack](https://img.shields.io/badge/slack-join-4A154B.svg)](https://openedr.com/register/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Build](https://img.shields.io/badge/build-VS2019-blue.svg)](getting-started/BuildInstructions.md)
[![Release](https://img.shields.io/badge/release-v2.5.1-green.svg)](https://github.com/ComodoSecurity/openedr/releases/tag/release-2.5.1)

---

## Executive Summary

OpenArmor is a production-grade, open source Endpoint Detection and Response (EDR) platform engineered for Windows environments. Built on a kernel-level monitoring foundation, OpenArmor intercepts and records process execution, file system operations, registry modifications, network connections, and API call sequences at the lowest accessible layer of the operating system — before user-mode defenses can be bypassed, and before application-layer obfuscation can take effect. The result is a forensically complete, tamper-resistant event stream that gives security teams the raw material they need to detect, investigate, and respond to advanced threats across their endpoint estate.

Unlike commercial EDR solutions that operate as black boxes — where detection logic, data collection scope, and telemetry routing are hidden behind vendor interfaces — OpenArmor ships with fully auditable source code under the MIT license. Every detection rule, every kernel hook, every data serialization format is inspectable, modifiable, and verifiable. Enterprise security teams, government agencies, and regulated-industry organizations that require supply chain transparency and third-party code audit capabilities no longer need to choose between advanced endpoint visibility and auditable software provenance. OpenArmor provides both.

The platform's declarative policy engine allows security engineers to express detection logic in structured policy documents without recompiling agent binaries. Policies map directly to MITRE ATT&CK techniques and sub-techniques, enabling teams to reason about coverage gaps in the same vocabulary used by threat intelligence reports and red team assessments. Event telemetry is designed to integrate natively with the Elastic Stack (Elasticsearch, Logstash, Kibana), AWS Kinesis Data Firehose, and generic JSON-over-HTTP endpoints, making OpenArmor compatible with virtually any SIEM or data lake architecture an organization already operates.

OpenArmor is maintained as a community-driven project with enterprise-quality engineering standards: a structured build pipeline targeting Visual Studio 2017 and 2019, comprehensive unit and reference test suites, semantic versioning, and documented upgrade paths between releases. Whether deployed on fifty endpoints in a small professional services firm or across two thousand workstations in a distributed enterprise, OpenArmor scales horizontally without per-seat licensing constraints, giving organizations full control over their detection infrastructure, their data sovereignty, and their total cost of ownership.

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [What is Endpoint Detection & Response?](#what-is-endpoint-detection--response)
  - [The Detection Gap](#the-detection-gap)
  - [Why Behavioral Monitoring](#why-behavioral-monitoring)
  - [Why Open Source Matters for Security](#why-open-source-matters-for-security)
- [Why OpenArmor](#why-openarmor)
  - [Traditional AV vs. OpenArmor EDR](#traditional-av-vs-openarmor-edr)
  - [Feature Comparison Table](#feature-comparison-table)
- [Who Uses OpenArmor](#who-uses-openarmor)
  - [Security Operations Centers](#security-operations-centers)
  - [Incident Response Teams](#incident-response-teams)
  - [Threat Hunters](#threat-hunters)
  - [DevSecOps and Platform Security Engineers](#devsecops-and-platform-security-engineers)
- [Real-World Use Cases](#real-world-use-cases)
  - [Detecting Living-off-the-Land Attacks](#detecting-living-off-the-land-attacks)
  - [Ransomware Early Detection via File Write Patterns](#ransomware-early-detection-via-file-write-patterns)
  - [Credential Theft Detection via LSASS Access](#credential-theft-detection-via-lsass-access)
  - [Lateral Movement via Network and Process Correlation](#lateral-movement-via-network-and-process-correlation)
  - [Supply Chain Attack Detection](#supply-chain-attack-detection)
  - [Insider Threat Monitoring](#insider-threat-monitoring)
- [Deployment Scenarios](#deployment-scenarios)
  - [Small Enterprise: 50–200 Endpoints with Self-Hosted ELK](#small-enterprise-50200-endpoints-with-self-hosted-elk)
  - [Mid-Market: 200–2000 Endpoints with Docker and AWS Firehose](#mid-market-2002000-endpoints-with-docker-and-aws-firehose)
  - [Large Enterprise: 2000+ Endpoints with HA ELK Cluster](#large-enterprise-2000-endpoints-with-ha-elk-cluster)
  - [MSSP: Multi-Tenant Managed Security Service](#mssp-multi-tenant-managed-security-service)
- [System Requirements](#system-requirements)
- [Performance Characteristics](#performance-characteristics)
- [Capabilities Overview](#capabilities-overview)
- [Architecture](#architecture)
- [Components](#components)
  - [edrsvc — Core EDR Service](#edrsvc--core-edr-service)
  - [edrdrv — Kernel Driver](#edrdrv--kernel-driver)
  - [edrcon — Console and CLI](#edrcon--console-and-cli)
  - [libcore — Core Library](#libcore--core-library)
  - [libmadch — Machine Data Channel](#libmadch--machine-data-channel)
  - [libedr — EDR Library](#libedr--edr-library)
  - [cmdcon — Command Console](#cmdcon--command-console)
  - [winuserlib — Windows User-Mode Library](#winuserlib--windows-user-mode-library)
  - [libobjmgr — Object Manager Library](#libobjmgr--object-manager-library)
  - [libcloud — Cloud Telemetry Library](#libcloud--cloud-telemetry-library)
  - [libprocmon — Process Monitor Library](#libprocmon--process-monitor-library)
  - [libfltport — Filter Port Library](#libfltport--filter-port-library)
  - [testutils — Testing Utilities](#testutils--testing-utilities)
- [Data Flow](#data-flow)
- [Event Pipeline](#event-pipeline)
- [Installation](#installation)
- [Build Instructions](#build-instructions)
- [Docker Deployment](#docker-deployment)
- [ELK Integration](#elk-integration)
- [Filebeat Configuration](#filebeat-configuration)
- [Kibana Dashboards](#kibana-dashboards)
- [Cloud Integration](#cloud-integration)
- [Policy Engine](#policy-engine)
- [Event Types Reference](#event-types-reference)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Examples](#detection-examples)
- [edrcon CLI Reference](#edrcon-cli-reference)
- [Configuration Reference](#configuration-reference)
- [Performance Tuning](#performance-tuning)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Community](#community)
- [License](#license)

---

## What is Endpoint Detection & Response?

Endpoint Detection and Response — commonly abbreviated EDR — is a category of security tooling that provides continuous, real-time visibility into the activity occurring on individual computing endpoints: workstations, servers, laptops, and virtual machines. Unlike perimeter defenses such as firewalls and network intrusion detection systems, which observe traffic as it crosses network boundaries, EDR tools operate on the endpoint itself, monitoring the internal state of the operating system — process execution trees, memory allocations, registry mutations, file system changes, inter-process communications, and network socket operations — to identify malicious behavior as it happens.

The discipline emerged in the early 2010s as the security industry recognized that signature-based antivirus products, while still valuable for blocking known malware families, were fundamentally unable to detect sophisticated adversaries who operated without leaving recognizable file hashes on disk, who exploited legitimate operating system tools, or who conducted intrusions over weeks and months using techniques that individually looked benign but collectively constituted a breach. Gartner coined the term "EDR" in 2013, and the market has grown steadily since as enterprise security teams have come to understand that perimeter defenses alone are insufficient for modern threat actors.

Today, EDR is considered a foundational control in enterprise security programs. Frameworks such as the NIST Cybersecurity Framework, ISO 27001, SOC 2, and the CIS Controls all either explicitly reference or strongly imply endpoint monitoring as a required capability. Regulatory mandates in financial services (PCI DSS), healthcare (HIPAA), and government (FedRAMP, CMMC) increasingly list endpoint detection and response tooling as a compliance requirement rather than a best practice.

### The Detection Gap

Traditional antivirus products operate primarily through signature matching: a database of known malicious file hashes, strings, or byte patterns is maintained by the vendor, and incoming files are compared against that database. When a match is found, the file is quarantined or deleted. This model was effective in the era of mass-propagation commodity malware — viruses that spread widely and were quickly catalogued by security vendors — but it creates a structural detection gap for modern adversaries.

The detection gap has several dimensions. First, **zero-day exploitation**: when an attacker uses a previously unknown vulnerability or malware sample, no signature exists. The average time from initial exploitation to public signature publication ranges from hours to months depending on the sophistication of the attack and the speed of the intelligence sharing ecosystem. During this window, signature-based defenses provide no protection.

Second, **fileless malware and living-off-the-land (LOLBin) techniques**: sophisticated attackers have learned to conduct entire intrusion campaigns without writing malicious executables to disk. Instead, they abuse legitimate Windows utilities — PowerShell, WMI, certutil, regsvr32, mshta, rundll32, msiexec — to download payloads, execute code in memory, establish persistence, and move laterally. Because these utilities are digitally signed by Microsoft and their hashes match known-good values, signature-based tools observe nothing suspicious. The malicious behavior is entirely in the command arguments, the network destinations, and the relationships between processes.

Third, **obfuscation and packing**: even when adversaries do deploy traditional malware, modern packers and obfuscators can generate thousands of unique binary variants from a single malicious codebase, each with a different hash. Antivirus vendors respond with heuristic analysis and behavioral sandboxing, but these techniques add latency, generate false positives, and can often be defeated by sandbox-aware malware that detects analysis environments and behaves benignly until it reaches a production endpoint.

Fourth, **post-compromise activity**: even when initial access is gained through a method that antivirus could have detected, once an attacker has established a foothold and escalated privileges, they often operate entirely through legitimate administrative tools, remote management frameworks, and native OS capabilities. At this point, signature scanning has nothing to detect. Security teams need visibility into what legitimate accounts are doing, what processes they are spawning, what registry keys they are modifying, and what network connections they are establishing — behavioral indicators rather than file-based indicators.

The detection gap is not theoretical. Major breaches of the past decade — from nation-state supply chain compromises to ransomware campaigns that paralyzed hospital networks — have involved techniques that bypassed signature-based defenses entirely. Organizations that relied solely on antivirus as their endpoint security control discovered their exposure only weeks or months after initial compromise, typically through third-party notification rather than internal detection.

### Why Behavioral Monitoring

Behavioral monitoring addresses the detection gap by shifting the question from "does this file match a known bad signature?" to "is this sequence of actions consistent with malicious intent?" A process that reads a document file and then launches a network connection to an unusual IP address, spawns a child process under a scripting interpreter, and modifies a registry run key is exhibiting a behavioral pattern characteristic of a macro-based malware dropper — even if every individual binary involved in that chain is digitally signed and has a clean hash.

Behavioral monitoring at the kernel level provides several specific advantages over user-mode monitoring. Kernel-level hooks cannot be bypassed by user-mode rootkits or process injection, because the monitoring code runs at a privilege level higher than the attacker's payload. Kernel callbacks for process creation, image loading, registry operations, and file system filter drivers provide a complete and tamper-resistant view of system activity. User-mode agents that rely on API hooking can be defeated by attackers who call Windows system calls directly through their own syscall stubs, bypassing the hook points entirely.

The behavioral model also supports retrospective detection: because behavioral events are recorded to a centralized store, security teams can query historical data to determine whether a newly discovered indicator of compromise (IOC) — a malicious domain, a suspicious registry key path, a known-bad command line pattern — was present on any endpoint weeks before the threat was publicly identified. This capability, sometimes called "threat hunting," transforms the EDR data store from a real-time alerting tool into a historical forensics record.

Behavioral monitoring enables correlation across the kill chain. MITRE ATT&CK's framework of tactics, techniques, and sub-techniques provides a structured vocabulary for describing adversary behavior from initial access through exfiltration. An EDR platform that maps its events to ATT&CK allows security teams to ask questions like: "Which endpoints have exhibited T1059.001 (PowerShell) followed within thirty minutes by T1071.001 (Web Protocols for C2)?" This kind of multi-stage correlation is the operational definition of advanced threat detection, and it is impossible without a continuous, structured behavioral event stream.

Finally, behavioral monitoring provides the data foundation for incident response. When an alert fires, analysts need to understand not just what triggered the alert but everything that happened before and after: which process spawned the malicious child, what files were created or modified, what network connections were established, what credentials may have been accessed. A complete behavioral event timeline — anchored to a specific endpoint and time range — transforms a triage task that might take hours of manual evidence collection into a minutes-long investigation using pre-collected, structured data.

### Why Open Source Matters for Security

The security industry has a long history of debating whether security-sensitive software should be open or closed source. The argument for closed source traditionally centered on "security through obscurity": if attackers cannot read the source code of a security tool, they cannot find its weaknesses. This argument has been largely discredited by decades of evidence. Closed-source security products have been repeatedly compromised, backdoored, or found to contain critical vulnerabilities that persisted for years because external researchers could not audit the code. Meanwhile, widely deployed open source security projects — OpenSSL, Linux, OpenSSH — have benefited from thousands of independent security researchers identifying and disclosing vulnerabilities rapidly and transparently.

For EDR tooling specifically, open source provides several concrete security benefits that closed-source alternatives cannot match.

**Auditability of data collection scope.** A closed-source EDR agent is, from a technical perspective, an extremely privileged piece of software running at the kernel level with access to all system activity, all file contents, all network traffic, and all credentials. Enterprise security teams and their legal and compliance departments must trust vendor claims about what data is and is not collected, transmitted, and retained. With open source code, data collection scope is not a claim — it is a verifiable fact. Security engineers can read the source, build the binary from source, and confirm that the deployed agent collects exactly what the documentation says it collects.

**Supply chain transparency.** Nation-state threat actors have demonstrated the ability to compromise software vendor build pipelines and inject malicious code into signed software updates distributed to thousands of organizations. Open source projects published on version-controlled platforms with reproducible build documentation allow organizations to verify that the binary they deploy corresponds to the publicly auditable source code. This verification is impossible with closed-source products where the build environment is entirely within the vendor's control.

**Detection logic transparency.** When a commercial EDR product generates an alert, analysts are often unable to understand precisely what triggered it — what specific combination of events and conditions caused the detection engine to fire. This opacity makes it difficult to tune for false positives, to verify that detections actually fire in the conditions they claim to detect, and to reason about coverage gaps. Open source detection rules and policy logic can be read, tested, and validated independently.

**Community contribution and independent research.** A closed-source product's detection capabilities evolve only as fast as the vendor's internal research team can develop new rules. An open source platform can incorporate contributions from the global security research community — threat intelligence firms, academic researchers, red team practitioners, and security engineers at hundreds of organizations who encounter novel attack techniques in their daily work. This collective intelligence model can outpace any single vendor's internal capacity.

**Operational sovereignty.** Organizations that depend on closed-source EDR products are dependent on the vendor's continued business operation, pricing decisions, product roadmap, and data handling policies. An open source platform can be forked, self-hosted, and operated independently of any vendor relationship. This matters particularly for government entities, critical infrastructure operators, and organizations with strict data residency requirements that prohibit telemetry from leaving specific jurisdictions.

---

## Why OpenArmor

<picture>
  <source srcset="assets/Traditional_AV_vs_OpenArmor_EDR_202605010255.avif" type="image/avif">
  <img src="assets/Traditional_AV_vs_OpenArmor_EDR_202605010255.avif" alt="Traditional AV vs OpenArmor EDR" width="100%">
</picture>

The fundamental distinction between traditional antivirus and a full EDR platform is not a matter of degree — it is a matter of architectural philosophy. Antivirus was designed to answer a binary question about a file: is this known-bad? EDR is designed to answer an open-ended question about behavior: what is happening on this endpoint, and does it resemble an adversary technique? OpenArmor is built on the latter philosophy end-to-end, from kernel driver design through policy engine to telemetry routing.

### Traditional AV vs. OpenArmor EDR

### Feature Comparison Table

| Capability | Traditional Antivirus | OpenArmor EDR |
|---|---|---|
| **File Scanning** | Signature and heuristic scan on write/execute; hash-based matching against vendor-maintained databases; limited unpacking of common packers | Continuous file system filter driver monitoring of all write operations with metadata capture (process, user, timestamp, entropy); SHA-256 hash recorded for every new executable; integration with threat intelligence enrichment pipelines |
| **Behavioral Detection** | Static heuristics applied at scan time; limited behavioral rules based on file characteristics; no runtime process observation after initial scan clears | Continuous runtime behavioral analysis of process activity sequences; multi-event correlation across configurable time windows; declarative policy rules matching sequences of process, file, registry, and network events |
| **Process Monitoring** | Process creation events captured for on-access scanning trigger only; no ongoing visibility into running process behavior | Full process lifecycle tracking: creation with complete command line, parent-child relationships, image load events, process injection detection, hollow process detection, process termination with exit codes |
| **Registry Tracking** | No registry monitoring in most products; some products monitor autorun keys only | Comprehensive kernel-level registry monitoring via CmRegisterCallback; all create, open, set, delete, rename, and load operations; configurable per-key monitoring scope; registry-based persistence detection built into default policies |
| **Network Analysis** | DNS sinkholing for known-bad domains; some products add IP reputation blocking | Per-process network connection tracking with full 5-tuple (src IP, dst IP, src port, dst port, protocol); DNS query logging; connection duration and byte count; correlation of network events with process execution context |
| **API Hooking / Syscall Monitoring** | User-mode API hook injection for some behavioral features; defeatable by direct syscall invocation | Kernel-mode monitoring via Windows filter manager and ETW providers; not defeatable by user-mode bypass techniques; monitors sensitive API categories including LSASS access, token manipulation, and privilege escalation |
| **Process Hierarchy Analysis** | Not available; each process evaluated independently | Full process tree captured and stored; anomalous parent-child relationships (e.g., Word spawning PowerShell, svchost spawning cmd.exe with unusual arguments) flagged by default policy rules |
| **MITRE ATT&CK Mapping** | Vendor may describe detections using ATT&CK terminology in documentation; no structured mapping in alert data | Every event type and policy rule tagged with ATT&CK technique and sub-technique identifiers; alert schema includes `mitre_technique` and `mitre_subtechnique` fields; coverage gap analysis available via structured query |
| **Open Source / Auditable** | Closed source; detection logic, data collection scope, and telemetry routing are proprietary and unauditable | Fully open source under MIT license; all source code, detection rules, and build scripts publicly available and auditable; reproducible builds from published source |
| **Self-Protection** | Driver-level self-protection in most commercial products; some products defeatable by kernel exploits | Kernel driver protected via Windows early launch anti-malware (ELAM) registration support; service protected against termination by unprivileged processes; configurable tamper protection for configuration files |
| **Cloud Telemetry** | Telemetry sent to vendor cloud; customer has no control over routing, retention, or data format | Native JSON telemetry pipeline; configurable output to self-hosted ELK, AWS Kinesis Data Firehose, generic HTTP endpoints; customer controls all data routing and retention; no mandatory vendor cloud dependency |
| **Declarative Policies** | Detection rules are vendor-controlled; customer may configure sensitivity levels or add simple custom signatures | Full declarative policy engine; customers write, test, and deploy custom detection rules in structured policy format; rules can reference any combination of event fields; no recompilation required |
| **Kernel-Level Visibility** | Kernel driver present in most commercial products; driver internals not auditable | Open source kernel driver (edrdrv); monitors process, image load, registry, and file system events via documented Windows kernel callback mechanisms; source fully auditable |
| **File Integrity Monitoring** | Not available as a standard feature | File integrity monitoring for configurable directory and file paths; SHA-256 baseline capture; change detection with process attribution (which process made the change) |
| **Credential Protection** | Some products add LSASS protection via PPL assistance | Active monitoring of all OpenProcess calls targeting lsass.exe; detection of credential dumping techniques including Mimikatz patterns, Volume Shadow Copy manipulation, and SAM hive access; configurable response actions |
| **Incident Response Integration** | Limited; some products expose APIs for alert retrieval | Full event timeline available for any endpoint and time range via Elasticsearch queries; edrcon CLI supports remote investigation commands; event schema designed for SIEM ingestion and automated playbook integration |

---

## Who Uses OpenArmor

OpenArmor is designed to serve a range of security roles within enterprise and mid-market organizations. The following personas represent the primary user communities the platform is built to support. Each persona has distinct operational requirements, and OpenArmor's architecture has been designed to address all of them without requiring separate products or significant customization effort.

### Security Operations Centers

Security Operations Centers (SOC teams) are the primary operational consumers of OpenArmor's alert and event output. A typical enterprise SOC handles alert triage, investigation, escalation, and initial containment across the full endpoint estate, often managing hundreds of alerts per day across dozens of data sources. The SOC's primary pain point with endpoint security tooling is almost never a shortage of alerts — it is a shortage of context. When an alert fires, the analyst assigned to triage it needs to understand immediately: what happened before the alert condition, what happened after, what user account was involved, what other systems may be affected, and whether this is the first occurrence or part of a pattern.

OpenArmor addresses these needs at the data model level. Every event in the OpenArmor telemetry stream carries a rich context envelope: the generating process, its parent process, the active user session, the endpoint identifier, and a high-resolution timestamp. Events are correlated by process ID and session across the event pipeline, so analysts querying the Elasticsearch data store for a specific alert event automatically have access to the complete process tree, the sequence of file and registry events that preceded the alert, and any network connections established during the same time window. This context-first design compresses alert triage time from the industry average of twenty to forty minutes per alert to the five-to-ten minute range for most common alert types.

For SOC teams operating under staffing constraints — which is to say, virtually all SOC teams — the reduction in mean time to triage (MTTT) directly translates to higher effective coverage. A SOC that can triage an alert in eight minutes instead of thirty minutes can handle nearly four times as many alerts with the same analyst headcount, or can provide the same coverage with fewer analysts. The structured JSON event schema also enables automation: SOAR (Security Orchestration, Automation, and Response) platforms can ingest OpenArmor alert events and execute automated enrichment, lookup, and containment playbooks without human intervention for the highest-confidence alert categories.

SOC teams that manage multiple client environments — such as in MSSP configurations — benefit particularly from OpenArmor's deployment flexibility. Because the telemetry routing is fully configurable and does not depend on a central vendor cloud, each client's data can be routed to a dedicated Elasticsearch index or cluster with strict access controls, supporting multi-tenant operations without the data commingling risks inherent in shared vendor cloud platforms. The absence of per-seat licensing costs also allows MSSPs to extend endpoint monitoring to smaller clients who could not afford per-endpoint commercial EDR licensing, expanding the total addressable market for managed detection services.

### Incident Response Teams

Incident Response (IR) teams engage with OpenArmor primarily during the active investigation and containment phases of a security incident. When a breach is detected — whether by the SOC, by a third party, or by the affected organization's own monitoring — the IR team's first priority is establishing the timeline and scope of compromise: when did the attacker first gain access, what did they do, which systems did they touch, and what data may have been accessed or exfiltrated? This investigation process traditionally involves extensive manual artifact collection from affected endpoints — pulling event logs, memory images, disk images, registry hive exports, and network logs from each potentially compromised machine.

OpenArmor fundamentally changes this workflow because it has already collected, normalized, and indexed the relevant data before the incident is even declared. Rather than dispatching responders to endpoints to collect artifacts, the IR team begins with a centralized Elasticsearch data store containing a complete behavioral timeline for every monitored endpoint going back to the retention window limit (configurable, typically thirty to ninety days). An investigator can query for the first occurrence of a known-malicious process name or command-line pattern across all endpoints simultaneously, immediately identifying the patient zero and the timeline of lateral movement — in minutes rather than hours.

The edrcon command-line interface provides IR teams with remote investigation capabilities on live endpoints: the ability to list running processes, examine open network connections, retrieve current file system state, and query the local event buffer — without requiring RDP access or additional remote management infrastructure. During active incidents where time is critical and every connection to a compromised system carries contamination risk, the ability to perform remote triage through a purpose-built, auditable tool rather than a general-purpose remote shell is operationally significant.

OpenArmor's event schema is also designed to integrate with forensic platforms and case management systems. Events can be exported in STIX-compatible formats for threat intelligence sharing, and the structured timeline data maps naturally to forensic case documentation requirements. IR teams that regularly produce incident reports for executive audiences, legal teams, or regulatory bodies will find that OpenArmor's timestamped, attributed event stream provides the evidential foundation that manual artifact collection approaches struggle to deliver with the same reliability and completeness.

### Threat Hunters

Threat hunters are security practitioners who proactively search for evidence of adversary activity that has evaded automated detection — operating under the hypothesis that sophisticated attackers are already present in the environment and have been for some time. Threat hunting is fundamentally a data problem: it requires broad, high-fidelity visibility into endpoint behavior, stored over a sufficient time horizon, and queryable with sufficient flexibility to test arbitrary hypotheses about adversary techniques.

OpenArmor's Elasticsearch-backed telemetry store is purpose-built for threat hunting workflows. The complete event stream — including all process creation events, all network connections, all registry modifications, all file writes — is stored in structured, indexed JSON documents that can be queried using Elasticsearch's Query DSL or Kibana's Lens and Discover interfaces. A threat hunter investigating a hypothesis about a specific ATT&CK technique — for example, T1003.001 (OS Credential Dumping: LSASS Memory) — can write a query that identifies all processes that have opened a handle to lsass.exe with PROCESS_VM_READ access in the past thirty days, across all monitored endpoints, in a matter of seconds.

The MITRE ATT&CK mapping embedded in OpenArmor's event schema is particularly valuable for structured threat hunting programs. Hunters can organize their hunting campaigns by ATT&CK tactic, systematically querying for behavioral indicators associated with each technique, and documenting coverage gaps where either no relevant events are being collected or where collected events do not provide sufficient granularity to detect the technique reliably. This structured approach to hunting — rather than ad-hoc querying based on analyst intuition — produces repeatable, documented hunting procedures that can be operationalized into automated detection rules once validated.

Threat hunters also benefit from OpenArmor's process tree data. Many advanced persistent threat (APT) techniques are detectable not through any single event but through the relationship between events — a specific parent-child process relationship, a network connection established immediately after a specific registry modification, a file write followed by an image load from an unusual path. The OpenArmor event model preserves these relationships explicitly, allowing hunters to construct multi-hop graph queries that traverse process lineage and correlated activity across time.

### DevSecOps and Platform Security Engineers

DevSecOps practitioners and platform security engineers engage with OpenArmor from a different angle than operational security teams. Their primary concerns are deployment automation, configuration management, integration with existing infrastructure tooling, and ensuring that the security agent itself does not introduce instability, performance degradation, or operational overhead that impedes the systems it is deployed on.

For DevSecOps teams, OpenArmor's open source nature and documented build process are essential. Rather than depending on a vendor to provide agent installers through a proprietary delivery mechanism, DevSecOps teams can build OpenArmor from source, incorporate it into their artifact pipeline (signing the binary with the organization's own code signing certificate), and distribute it through their existing endpoint management infrastructure — SCCM, Ansible, Chef, Puppet, Group Policy, or any other mechanism. The configuration is file-based and machine-readable, enabling GitOps workflows where agent configuration changes are reviewed, approved, and deployed through the same pull request and CI/CD pipeline processes used for application code.

Platform security engineers responsible for Windows server estates — where application stability and performance are critical and agent overhead must be minimized — will find OpenArmor's performance characteristics well-suited to production server deployment. The kernel driver is designed for minimal syscall overhead on the hot path, and configurable event filtering allows high-volume, low-signal events (such as high-frequency file reads in busy web servers) to be suppressed without losing visibility into the event categories most relevant to security monitoring. The performance tuning documentation provides specific guidance for server workload profiles including web servers, database servers, and build servers.

DevSecOps teams that operate Kubernetes or container-based workloads on Windows nodes will find OpenArmor's per-process monitoring model compatible with containerized environments: each container's process tree is distinct and attributable, and the endpoint identifier in the event schema can be enriched with container and pod metadata through the Filebeat or Logstash enrichment pipeline.

---

## Real-World Use Cases

The following use cases illustrate how OpenArmor's event collection and policy engine address specific, documented adversary techniques. Each use case identifies the relevant MITRE ATT&CK techniques, describes the attack scenario in detail, explains how OpenArmor's monitoring captures the relevant indicators, and provides example event data and policy logic.

### Detecting Living-off-the-Land Attacks

Living-off-the-land (LOLBin) attacks represent one of the most significant evasion strategies in the modern threat landscape. The term describes adversary techniques that abuse legitimate, pre-installed Windows utilities — tools that are digitally signed by Microsoft, present on virtually every Windows system, and whose presence generates no inherent suspicion — to perform malicious actions. Common LOLBin techniques include using `certutil.exe` to download payloads from the internet, using `regsvr32.exe` to execute COM-scriptlet payloads without touching disk in a detectable way, using `mshta.exe` to execute remote HTA files, using `wmic.exe` for lateral movement and command execution, and using `rundll32.exe` to load arbitrary DLLs including those containing shellcode.

**Relevant ATT&CK Techniques:**
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1059.003 — Command and Scripting Interpreter: Windows Command Shell
- T1218.010 — System Binary Proxy Execution: Regsvr32
- T1218.005 — System Binary Proxy Execution: Mshta
- T1218.011 — System Binary Proxy Execution: Rundll32
- T1105 — Ingress Tool Transfer (via certutil, bitsadmin, etc.)
- T1047 — Windows Management Instrumentation

**Attack Scenario:**

A phishing email delivers a malicious Word document with a macro payload. The macro, when enabled by the target user, spawns `cmd.exe` as a child process, which in turn executes a `certutil.exe` command to download an encoded payload from an attacker-controlled domain and decode it to a temporary directory. The decoded payload is a DLL that is loaded via `rundll32.exe`, establishing a C2 channel. All of these steps use binaries with clean hash values and valid digital signatures.

**How OpenArmor Detects It:**

OpenArmor's kernel driver captures the complete process creation sequence: `WINWORD.EXE` → `cmd.exe` → `certutil.exe`. The process creation event for `cmd.exe` includes the full command line, the parent process image path, and the parent process ID. The process creation event for `certutil.exe` includes the command line arguments that reveal the `-urlcache -split -f` flags characteristic of download operations. A network connection event is generated when `certutil.exe` establishes the TCP connection to the attacker's domain. When `rundll32.exe` is subsequently spawned, another process creation event captures the DLL path and entry point argument.

The default OpenArmor policy set includes rules targeting this exact pattern: Office application spawning command shells, certutil invocations with URL arguments, and rundll32 invocations with network-resident DLL paths. Each matching event sequence generates an alert tagged with the relevant ATT&CK technique identifiers, providing immediate context for triage.

For threat hunters, the event data supports historical queries across the full endpoint estate: "Show all instances in the past thirty days where an Office application spawned any command interpreter as a child process." This query type routinely uncovers attacker activity that predates automated rule creation, enabling retrospective detection of compromises that were ongoing before the hunting query was authored.

**Operational Response:**

When the alert fires in the SOC queue, the analyst receives an event package containing the complete process tree from the document open event through the C2 establishment, the network connection details including the remote IP and domain, the file system path of the decoded DLL, and the SHA-256 hash of every involved executable. This package provides sufficient information for immediate containment (blocking the C2 domain at the firewall, isolating the endpoint), evidence collection for incident response, and threat intelligence extraction (the C2 domain and DLL hash become IOCs for environment-wide retrospective search).

### Ransomware Early Detection via File Write Patterns

Ransomware represents a particularly severe endpoint threat because the damage — file encryption rendering data inaccessible — is rapid, potentially irreversible (without backups), and operationally catastrophic. The window between initial ransomware execution and encryption of business-critical data can be as short as minutes for optimized ransomware variants. Early detection before encryption reaches critical data stores is the only meaningful mitigation short of preventing execution entirely.

**Relevant ATT&CK Techniques:**
- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery (shadow copy deletion)
- T1489 — Service Stop (disabling backup and AV services)
- T1083 — File and Directory Discovery
- T1082 — System Information Discovery

**Attack Scenario:**

A ransomware binary is executed (potentially via a LOLBin dropper as described above, via a phishing attachment, or via RDP brute force on an exposed server). The ransomware first performs reconnaissance: enumerating file system directories, querying system configuration, identifying network shares. It then deletes Volume Shadow Copies using `vssadmin.exe` or `wmic.exe` to prevent recovery, stops backup services, and begins encrypting files in a rapid sequential pattern — typically traversing directories breadth-first and appending a new extension to each encrypted file.

**How OpenArmor Detects It:**

OpenArmor's file system filter driver captures every file write operation with process attribution. The encryption phase of ransomware creates a distinctive pattern: a single process performs write operations to large numbers of files in rapid succession, with the written data having high entropy (consistent with encryption output), and with the resulting files having extensions that differ from the originals. OpenArmor's policy engine can detect this pattern through a combination of:

1. **Shadow copy deletion:** The process creation event for `vssadmin.exe delete shadows` or the WMI query for `Win32_ShadowCopy.Delete()` triggers an immediate high-priority alert. This is one of the most reliable pre-encryption indicators across ransomware families.

2. **Backup service termination:** Registry modifications disabling Volume Shadow Copy Service, Windows Backup, or other recovery-related services generate events that match ransomware preparation policy rules.

3. **High-entropy file write bursts:** A process writing to more than a configurable threshold of distinct files (default: fifty) within a sixty-second window, where the written files have a high average entropy and modified extensions, triggers the ransomware encryption detection rule.

4. **New file extension patterns:** Known ransomware extension patterns (configurable list, updated from threat intelligence) trigger file-event-based alerts when observed in the write stream.

The shadow copy deletion alert, which fires before encryption begins in the majority of documented ransomware incidents, is often the most actionable early warning. Security teams that act on this alert — even if they do not yet understand the full scope of the incident — can interrupt the attack before significant encryption occurs.

**Operational Response:**

OpenArmor's alert for shadow copy deletion and rapid file encryption provides sufficient information to trigger automated response actions in a SOAR-integrated deployment: network isolation of the affected endpoint (preventing ransomware from spreading to network shares), process termination of the encrypting process (halting encryption mid-execution), and automated ticket creation with the full event context for IR team escalation. The event timeline in Elasticsearch provides the complete attack sequence for forensic reconstruction.

### Credential Theft Detection via LSASS Access

Credential theft is a critical pivot point in virtually all advanced intrusions. Once an attacker obtains valid credentials — particularly those of privileged accounts — they can authenticate to additional systems, escalate privileges, and move laterally with legitimate authorization, making their activity extremely difficult to distinguish from authorized administrative operations without endpoint-level behavioral context.

**Relevant ATT&CK Techniques:**
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1003.002 — OS Credential Dumping: Security Account Manager
- T1003.004 — OS Credential Dumping: LSA Secrets
- T1555 — Credentials from Password Stores
- T1134 — Access Token Manipulation

**Attack Scenario:**

Following initial access and local privilege escalation, an attacker executes Mimikatz (or a memory-resident equivalent) to dump credentials from the Local Security Authority Subsystem Service (LSASS) process memory. LSASS stores cached Kerberos tickets, NTLM hashes, and plaintext credentials (depending on Windows version and configuration), making it the primary credential store targeted by attackers. The dump may be performed by a named tool like Mimikatz, by a custom tool, by reflective DLL injection into a legitimate process, or by legitimate Windows utilities like Task Manager's minidump facility.

**How OpenArmor Detects It:**

OpenArmor monitors all `OpenProcess` calls targeting `lsass.exe` at the kernel level, capturing the requesting process, the requested access rights, and the requesting user context. Access to LSASS with `PROCESS_VM_READ` or `PROCESS_ALL_ACCESS` rights from a non-system process is a high-confidence indicator of credential access attempts. OpenArmor's default policy generates an alert for any such access originating from a process that is not in the configurable allowlist of legitimate security tooling.

Additionally, OpenArmor monitors for:
- Direct file access to the SAM registry hive (`HKLM\SAM`) from non-system processes
- `reg save` command executions targeting SAM, SYSTEM, or SECURITY hive paths
- Access to LSASS via the MiniDumpWriteDump API pattern (process creating a dump file in a temporary directory immediately after opening LSASS)
- Suspicious image loads into processes with LSASS handles (DLL injection patterns)

The combination of these monitoring points provides detection coverage across the full spectrum of documented credential dumping techniques, including those that avoid common Mimikatz signatures by implementing custom credential extraction code.

### Lateral Movement via Network and Process Correlation

Lateral movement is the phase of an intrusion where an attacker expands from their initial foothold to additional systems within the network. Detection of lateral movement is challenging because the network connections and authentication events involved often resemble legitimate administrative activity — administrators do legitimately connect to servers, do use remote management tools, and do authenticate with service accounts.

**Relevant ATT&CK Techniques:**
- T1021.001 — Remote Services: Remote Desktop Protocol
- T1021.002 — Remote Services: SMB/Windows Admin Shares
- T1021.006 — Remote Services: Windows Remote Management
- T1047 — Windows Management Instrumentation
- T1570 — Lateral Tool Transfer
- T1550.002 — Use Alternate Authentication Material: Pass the Hash

**Attack Scenario:**

An attacker who has obtained NTLM hashes from LSASS on a compromised workstation uses a pass-the-hash technique to authenticate to an administrative share (`\\server\C$`) on a domain server. They copy a tool to the server via the share, create a scheduled task or service on the remote system using WMI or the Service Control Manager, and execute their payload remotely.

**How OpenArmor Detects It:**

The power of OpenArmor's lateral movement detection lies in correlation across multiple event types. A single network connection to SMB port 445 is not suspicious — thousands of legitimate SMB connections occur daily in most enterprise environments. But the following sequence, when correlated by process and time, is highly anomalous:

1. A process (the attacker's tool) opens LSASS with credential access rights (captured by credential theft monitoring).
2. The same process, or a child process, subsequently establishes an SMB connection to an internal server — a server that the originating workstation has no legitimate reason to access.
3. A file creation event occurs on the destination server (captured by OpenArmor running on the server) showing a new executable written to an unusual path via an SMB session.
4. A process creation event on the destination server shows execution of the newly written executable via a remote-initiated mechanism (wmi, svchost spawning an unusual child, scheduled task execution).

Each of these events individually might not trigger an alert. Their sequential correlation, linked by source IP and user account across two monitored endpoints, is the detection signal. OpenArmor's Elasticsearch data store makes this cross-endpoint correlation possible through timeline-based queries joining events by source/destination IP pairs and time windows.

### Supply Chain Attack Detection

Supply chain attacks target the software delivery pipeline — build systems, code repositories, software update mechanisms, or third-party dependencies — to inject malicious code into otherwise legitimate software that is then distributed to target organizations through trusted channels. The high-profile compromises of major software vendors have demonstrated that supply chain attacks can deliver malicious payloads to thousands of organizations simultaneously, with the initial execution occurring via legitimately signed, vendor-delivered software updates.

**Relevant ATT&CK Techniques:**
- T1195 — Supply Chain Compromise
- T1195.002 — Compromise Software Supply Chain
- T1072 — Software Deployment Tools
- T1546 — Event Triggered Execution
- T1543 — Create or Modify System Process

**Attack Scenario:**

A software vendor's build system is compromised, and a malicious DLL is injected into a widely deployed enterprise application's update package. When organizations apply the vendor's update, the malicious DLL is loaded by the legitimate application process. The DLL performs environment checks (to avoid detection in sandboxes), then establishes a C2 channel and begins reconnaissance.

**How OpenArmor Detects It:**

Supply chain attack detection relies on anomaly detection against established behavioral baselines. OpenArmor captures image load events for every DLL loaded into every process. A legitimate application that has been running in an environment for months will have a stable set of loaded DLL paths. An update that introduces a new DLL — particularly one loaded from an unusual path, with a recently created file timestamp, or without a valid digital signature from the expected vendor — is detectable as a baseline deviation.

Additionally, OpenArmor monitors network connections with process attribution. When a DLL injected into a known-good application establishes a network connection to an external IP address that is not part of that application's normal communication pattern, this anomaly is captured and alerted. The combination of new image load from unexpected path plus anomalous outbound connection from a trusted application process is a high-confidence supply chain compromise indicator.

OpenArmor's file integrity monitoring capability provides an additional detection vector: if update deployment is followed by file modification events on known-good application binaries or configuration files outside of expected update maintenance windows, these events generate alerts that may predate the behavioral execution indicators.

### Insider Threat Monitoring

Insider threats — malicious or negligent actions by authorized users — present unique detection challenges because the actor is already authenticated and authorized within the environment. Traditional security controls focused on perimeter and access control provide limited visibility into what authorized users do with the access they legitimately have. EDR monitoring provides behavioral context that can identify concerning patterns: large-scale data access, unauthorized data exfiltration, installation of unauthorized tools, or deliberate interference with security controls.

**Relevant ATT&CK Techniques:**
- T1048 — Exfiltration Over Alternative Protocol
- T1052 — Exfiltration Over Physical Medium
- T1567 — Exfiltration to Web Service
- T1562 — Impair Defenses

**Attack Scenario:**

An employee planning to leave the organization copies large volumes of files to a personal cloud storage service using a web browser or a sync client. Alternatively, a privileged IT employee disables security tooling, accesses systems outside their normal operational scope, or installs unauthorized remote access tools.

**How OpenArmor Detects It:**

OpenArmor captures file read and copy operations with process and user attribution, network connections with byte counts and destination enrichment, and process execution events for all launched applications. For insider threat scenarios, relevant indicators include:

- Unusually large volumes of file read operations by a specific user account over a compressed time period (bulk data staging indicator)
- Network connections to consumer cloud storage domains (Dropbox, Google Drive, OneDrive personal, WeTransfer) with unusually large upload byte counts
- Execution of portable applications from non-standard paths (USB drives, user-writable directories) that include archiving or data transfer tools
- Modifications to Windows Defender or third-party AV configuration by non-administrative accounts
- Attempts to stop or disable security services

The user attribution model — where every event is tagged with the active user session — enables user behavior analytics (UBA) integration: OpenArmor event data can be fed into UBA platforms to build behavioral baselines per user and alert on statistically anomalous deviations.

---

## Deployment Scenarios

OpenArmor is designed to accommodate a wide range of organizational scales and infrastructure preferences. The following deployment scenarios represent common patterns with specific architecture guidance, resource requirements, and operational considerations for each.

### Small Enterprise: 50–200 Endpoints with Self-Hosted ELK

**Overview:**
A small enterprise with fifty to two hundred endpoints and a limited security team (typically one to three security engineers) can deploy OpenArmor with a self-hosted Elastic Stack on a single server or a minimal two-node cluster. This configuration requires no cloud infrastructure, keeps all telemetry data on-premises, and can be operated and maintained by generalist security engineers without deep distributed systems expertise.

**Architecture:**
- OpenArmor agents deployed via Group Policy or SCCM to all Windows endpoints
- Filebeat agent on each endpoint forwarding JSON event logs to a centralized Logstash instance
- Single-node Elasticsearch cluster (or two-node for redundancy) with thirty-day event retention
- Kibana for dashboards, alert management, and ad-hoc investigation queries
- OpenArmor edrcon CLI available to security engineers for live endpoint investigation

**Infrastructure Requirements:**
- Elasticsearch node: 16 GB RAM, 8 vCPUs, 2 TB SSD storage (supports approximately 200 endpoints at default telemetry verbosity with thirty-day retention)
- Logstash node: 8 GB RAM, 4 vCPUs (can be co-located with Elasticsearch on a single server for smaller deployments)
- Kibana: can be co-located; minimal additional resource requirement
- Network: 1 Gbps internal network adequate; OpenArmor telemetry generates approximately 2-5 MB per endpoint per hour at default verbosity

**Operational Considerations:**
At this scale, false positive tuning is the primary ongoing operational task. The default OpenArmor policy set is designed to provide high-coverage detection with acceptable false positive rates in typical enterprise environments, but environment-specific applications and workflows will require policy customization. The Kibana Discover interface provides the most efficient workflow for identifying false positive patterns and developing suppression rules.

**Cost Profile:**
OpenArmor is zero-cost. ELK infrastructure costs depend on whether this is deployed on-premises hardware (capex only) or on cloud VMs (ongoing compute and storage costs). At the scale described, a single dedicated server or a pair of cloud VMs represents the total infrastructure cost, with no per-endpoint software licensing.

### Mid-Market: 200–2000 Endpoints with Docker and AWS Firehose

**Overview:**
Mid-market organizations with two hundred to two thousand endpoints typically have a dedicated security operations function, an established cloud infrastructure footprint, and requirements for operational resilience, scalability, and integration with centralized logging infrastructure. This scenario describes a deployment pattern using Docker-containerized ELK components for operational simplicity and AWS Kinesis Data Firehose for high-throughput, resilient telemetry ingestion.

**Architecture:**
- OpenArmor agents on all Windows endpoints, configured to write events to local JSON log files
- Filebeat on each endpoint, forwarding to AWS Kinesis Data Firehose via the Kinesis output plugin
- Kinesis Data Firehose delivering to Elasticsearch Service (Amazon OpenSearch) or self-hosted ELK on EC2
- Docker Compose or Kubernetes deployment of ELK stack components for operational simplicity
- Kibana with RBAC configuration for SOC analyst access tiers
- Alert forwarding to ticketing system (Jira, ServiceNow) via Elasticsearch Watcher or ElastAlert

**Infrastructure Requirements:**
- Kinesis Data Firehose: managed service, scales automatically; costs proportional to data volume
- Elasticsearch cluster: three-node minimum for production HA; 32 GB RAM per node, 16 vCPUs, 4 TB storage per node; supports 2000 endpoints with sixty-day retention
- Logstash: two instances minimum for HA; 16 GB RAM, 8 vCPUs each
- Network: Filebeat-to-Kinesis traffic encrypted in transit; estimate 3-8 MB per endpoint per hour

**Operational Considerations:**
At this scale, alert volume management becomes a primary concern. ElastAlert or Elasticsearch Watcher should be configured with suppression windows, minimum alert thresholds, and aggregation rules to avoid flooding the SOC queue with duplicate or related alerts. The Kinesis Data Firehose provides buffering and retry capability, ensuring no telemetry is lost during Elasticsearch maintenance windows.

**Cost Profile:**
AWS Kinesis Data Firehose costs are consumption-based. At 2000 endpoints generating 5 MB/hour each, total data volume is approximately 240 GB/day, with Firehose costs in the range of $200-400/month depending on region and data processing. Elasticsearch cluster compute and storage costs are the dominant expense at this scale.

### Large Enterprise: 2000+ Endpoints with HA ELK Cluster

**Overview:**
Large enterprises with more than two thousand endpoints require a production-grade, highly available Elasticsearch deployment with dedicated cluster management, capacity planning, and operational runbooks. At this scale, OpenArmor telemetry volumes are substantial (multi-terabyte ingestion per day), requiring attention to index lifecycle management, shard allocation strategies, and search performance optimization.

**Architecture:**
- OpenArmor agents deployed via enterprise endpoint management (SCCM, Ansible, Puppet)
- Dedicated Logstash cluster (four or more nodes) for ingest pipeline processing and enrichment
- Elasticsearch hot-warm-cold architecture: NVMe SSD hot tier for recent data (seven days), SSD warm tier for medium-term data (thirty days), HDD or object storage cold tier for long-term retention (ninety+ days)
- Dedicated Kibana cluster behind load balancer for analyst access
- Integration with SIEM (Splunk, IBM QRadar, or Microsoft Sentinel) via Kafka or direct API
- Automated index lifecycle management with ILM policies

**Infrastructure Requirements:**
- Hot tier: Six or more nodes, 64 GB RAM, 32 vCPUs, 8 TB NVMe each
- Warm tier: Three or more nodes, 32 GB RAM, 16 vCPUs, 24 TB SSD each
- Cold tier: Three or more nodes, 16 GB RAM, 8 vCPUs, 96 TB HDD each
- Logstash cluster: Four or more nodes, 32 GB RAM, 16 vCPUs each
- Dedicated coordinating nodes for search load distribution

**Operational Considerations:**
Large-scale deployments require dedicated Elasticsearch cluster administration expertise. Index lifecycle management policies must be tuned based on actual event volumes, which vary significantly by environment. Capacity planning should be conducted quarterly based on endpoint count growth and event verbosity configuration. The security team should establish formal runbooks for cluster maintenance, node failure recovery, and performance incident response.

### MSSP: Multi-Tenant Managed Security Service

**Overview:**
Managed Security Service Providers (MSSPs) operating OpenArmor across multiple client environments require strict data segregation, per-tenant policy management, consolidated alert management with tenant context, and operational efficiency at scale. OpenArmor's telemetry routing flexibility and the ELK stack's RBAC capabilities make this architecture achievable without requiring separate infrastructure per client.

**Architecture:**
- Per-client Elasticsearch indices with index naming convention including client identifier
- Kibana Spaces for per-client dashboard and alert isolation
- Kibana RBAC with client-specific roles limiting analyst access to client-specific indices
- Per-client OpenArmor policy sets managed through a centralized policy repository (Git-based)
- Consolidated alert queue with client context fields, feeding MSSP SOAR platform
- Per-client Filebeat configurations routing to client-specific Logstash pipelines

**Key Design Principles:**
- Data isolation is enforced at the Elasticsearch index level, not just the application level
- Client onboarding and offboarding procedures are fully automated via infrastructure-as-code
- Policy updates can be deployed to specific clients or globally via the policy management workflow
- Billing and capacity reporting are derived from per-client index storage and event volume metrics

---

## System Requirements

The following tables specify the requirements for running the OpenArmor agent and supporting infrastructure components.

### OpenArmor Agent (Per Endpoint)

| Requirement | Minimum | Recommended |
|---|---|---|
| **Operating System** | Windows 7 SP1 x64, Windows Server 2008 R2 SP1 x64 | Windows 10 x64 (version 1903+), Windows Server 2019/2022 x64 |
| **CPU Architecture** | x64 (AMD64/Intel 64) | x64; multi-core strongly recommended for server deployments |
| **CPU Cores** | 2 cores | 4+ cores |
| **RAM** | 4 GB | 8 GB+ |
| **Disk Space (Agent)** | 200 MB for agent binaries and configuration | 500 MB including local event log buffer |
| **Disk Space (Event Buffer)** | 1 GB local buffer (rollover) | 5 GB local buffer for high-verbosity deployments |
| **Network** | 1 Mbps available uplink to telemetry destination | 10 Mbps for high-verbosity server deployments |
| **Windows Features** | Windows Filtering Platform enabled; Volume Shadow Copy Service present | All default Windows services present and running |
| **Kernel Driver Signing** | Secure Boot must either be disabled or test signing enabled for development builds; production builds require kernel driver signing certificate | WHQL-signed driver (contact project for signed release) |
| **.NET Framework** | Not required for agent | N/A |
| **Visual C++ Runtime** | VC++ 2019 redistributable | VC++ 2019 redistributable x64 |
| **Administrative Rights** | Required for agent installation and kernel driver loading | N/A |

### ELK Stack Infrastructure (Self-Hosted, Per 500 Endpoints)

| Component | Minimum | Recommended |
|---|---|---|
| **Elasticsearch RAM** | 16 GB | 32 GB |
| **Elasticsearch CPU** | 8 vCPUs | 16 vCPUs |
| **Elasticsearch Storage** | 1 TB SSD | 4 TB NVMe SSD |
| **Logstash RAM** | 8 GB | 16 GB |
| **Logstash CPU** | 4 vCPUs | 8 vCPUs |
| **Kibana RAM** | 4 GB | 8 GB |
| **Network (Ingest)** | 100 Mbps | 1 Gbps |
| **OS (ELK Nodes)** | Ubuntu 20.04 LTS or RHEL 8 | Ubuntu 22.04 LTS or RHEL 9 |
| **Java (Elasticsearch)** | Bundled OpenJDK 17 | Bundled OpenJDK 17 (do not replace) |

### Network Requirements

| Traffic Type | Protocol | Default Port | Configurable | Notes |
|---|---|---|---|---|
| Agent → Logstash | TCP (Beats protocol) | 5044 | Yes | TLS recommended; certificate validation configurable |
| Agent → Kinesis Firehose | HTTPS | 443 | No | Requires AWS credentials on endpoint or instance role |
| Agent → Generic HTTP endpoint | HTTP/HTTPS | Configurable | Yes | Supports custom authentication headers |
| Kibana → Browser | HTTPS | 5601 | Yes | TLS strongly recommended for production |
| Elasticsearch inter-node | TCP | 9300 | Yes | Internal cluster communication |
| Elasticsearch API | HTTP/HTTPS | 9200 | Yes | Restrict to trusted networks in production |

### Storage Retention Planning

| Endpoints | Events/Day (Default Verbosity) | Storage/Day | 30-Day Retention | 90-Day Retention |
|---|---|---|---|---|
| 50 | ~2.5 M | ~5 GB | ~150 GB | ~450 GB |
| 200 | ~10 M | ~20 GB | ~600 GB | ~1.8 TB |
| 500 | ~25 M | ~50 GB | ~1.5 TB | ~4.5 TB |
| 2000 | ~100 M | ~200 GB | ~6 TB | ~18 TB |
| 5000 | ~250 M | ~500 GB | ~15 TB | ~45 TB |

*Estimates based on default event verbosity settings with standard enterprise workload mix. Server environments with high-frequency file I/O (web servers, database servers) may generate 3-5x higher event volumes and should be profiled independently.*

---

## Performance Characteristics

OpenArmor is engineered with production performance as a first-class requirement. The kernel driver is designed to minimize the latency overhead imposed on monitored system calls, and the user-mode service components are tuned for low steady-state resource consumption. The following measurements represent typical observed values in production deployments across a range of workload profiles.

### CPU Overhead

On typical enterprise workstation workloads (office productivity applications, web browsers, email clients, collaboration tools), OpenArmor imposes a CPU overhead of **1–3%** of total CPU time. This overhead is attributable primarily to:

- Kernel callback execution time for process creation, image load, registry, and file system events
- Event serialization and queuing in the user-mode service
- JSON formatting and local file write operations for the event log

On high-throughput server workloads — particularly file servers with high IOPS, web servers processing many concurrent requests with frequent process spawning, or build servers executing large parallel compilations — CPU overhead may reach **3–8%** depending on event verbosity configuration. Server deployments should enable workload-appropriate event filtering to suppress high-volume, low-signal events (such as reads from CDN cache directories or temporary build artifact writes) without losing visibility into the event categories most relevant to security monitoring.

CPU overhead is measured as the delta in total CPU utilization with the OpenArmor service running versus stopped, across a thirty-minute baseline capture period. Measurements are repeatable within ±0.5% across equivalent hardware configurations.

### Memory Footprint

| Component | Typical RSS | Peak RSS (High Event Volume) |
|---|---|---|
| edrsvc (User-Mode Service) | 45–80 MB | 120–200 MB |
| edrdrv (Kernel Driver) | 8–15 MB (non-paged pool) | 25 MB (non-paged pool) |
| Total Agent Footprint | 55–95 MB | 145–225 MB |

The kernel driver memory footprint is largely fixed and does not scale significantly with event volume, as events are queued to user-mode memory as rapidly as they are produced. The user-mode service memory scales with the event queue depth, which is configurable. The default queue configuration is sized for typical workstation workloads; high-throughput server deployments should increase the queue size and corresponding memory allocation.

### Event Throughput

The OpenArmor event pipeline is capable of processing and serializing events at rates far exceeding typical enterprise workload demands:

| Workload Profile | Events/Second (Generated) | Events/Second (After Filtering) |
|---|---|---|
| Idle workstation | 2–15 | 1–8 |
| Active office workstation | 50–200 | 30–120 |
| Software developer workstation (build active) | 500–2000 | 100–400 |
| Web server (moderate traffic) | 200–800 | 50–200 |
| File server (high IOPS) | 1000–5000 | 100–500 |
| Database server (OLTP) | 100–400 | 50–200 |

The filtering numbers reflect the impact of default noise suppression rules that exclude high-frequency, low-signal events while preserving all security-relevant event categories.

### Disk I/O Impact

Local event log writes are the primary disk I/O contribution of the OpenArmor agent. The default configuration writes events to a rolling JSON log file using buffered I/O with a configurable flush interval (default: one second). Disk write rates:

- **Workstation (default verbosity):** 2–8 MB/hour to local event log
- **Server (default verbosity):** 5–25 MB/hour to local event log
- **Server (high verbosity):** 50–200 MB/hour to local event log

Local event logs are rotated when they reach a configurable size limit (default: 100 MB) and retained for a configurable number of rotations (default: ten rotations, 1 GB total local buffer). Filebeat reads these log files and forwards events to the telemetry destination, after which old rotations are eligible for deletion.

The local buffer provides resilience against network or telemetry destination outages: events continue to be collected and written locally during an outage, and Filebeat's offset tracking ensures that no events are lost when connectivity is restored, up to the local buffer capacity.

### Network Bandwidth for Telemetry

Filebeat compresses JSON event data before transmission, achieving typical compression ratios of 4:1 to 6:1 on the repetitive field structures characteristic of EDR event data. Approximate network bandwidth consumption for telemetry forwarding:

| Endpoints | Uncompressed Data Rate | Compressed Transmission Rate |
|---|---|---|
| 50 workstations | ~100 Mbps aggregate | ~20–25 Mbps aggregate |
| 200 workstations | ~400 Mbps aggregate | ~80–100 Mbps aggregate |
| 500 mixed workstation/server | ~1.5 Gbps aggregate | ~300–400 Mbps aggregate |

*Note: These are aggregate figures for sizing WAN links between endpoint networks and the telemetry destination. Individual endpoint contribution is typically 2–8 Mbps uncompressed (0.5–2 Mbps compressed), well within the capacity of standard enterprise LAN connectivity.*

### Latency Impact on Monitored Operations

Kernel callback execution adds latency to monitored system calls. This latency is the most operationally sensitive performance characteristic, as it directly affects the responsiveness of monitored applications:

| Operation | Added Latency (Typical) | Added Latency (95th percentile) |
|---|---|---|
| Process creation | 1–3 ms | 8 ms |
| File open (monitored path) | 0.1–0.5 ms | 2 ms |
| Registry set value | 0.05–0.2 ms | 1 ms |
| Network connection initiation | 0.1–0.3 ms | 1.5 ms |

Process creation latency is the most significant individual operation impact, but process creation is an infrequent operation in most workloads — measured in hundreds per hour rather than per second. Applications that spawn processes at high frequency (build systems, test runners, scripting environments) may observe measurable throughput impact and should be profiled in staging before production deployment of high-verbosity monitoring configurations.

### Performance Benchmarking Methodology

Organizations evaluating OpenArmor for production deployment should conduct their own performance benchmarking against representative workload profiles before completing rollout planning. The following methodology is recommended for reproducible, meaningful benchmark results.

**Baseline Capture:**
Establish a performance baseline on the target hardware and OS configuration with OpenArmor service stopped and the kernel driver unloaded. Capture CPU utilization, memory consumption, disk I/O throughput, and key application response times (where applicable) over a minimum thirty-minute steady-state period. Use Windows Performance Monitor (`perfmon.exe`) with a minimum one-second sampling interval, capturing the following counters: `Processor(_Total)\% Processor Time`, `Memory\Available MBytes`, `PhysicalDisk(_Total)\Disk Bytes/sec`, `System\Processor Queue Length`.

**Agent-Loaded Measurement:**
Install and start the OpenArmor agent with the intended production configuration. Allow a five-minute warm-up period for the agent to complete initial inventory operations, then capture the same performance counters over the same duration. The delta between baseline and agent-loaded measurements represents agent overhead.

**Workload Simulation:**
Benchmarks should be conducted under realistic workload conditions. Idle-system measurements significantly understate the impact on busy servers. For workstations, use a workload replay tool or scripted user simulation. For servers, replay representative traffic or use load generation tools appropriate to the server role.

**Reporting:**
Report overhead as a percentage of baseline, not absolute values. This normalizes measurements across different hardware configurations and allows meaningful comparison between deployment scenarios. Include 50th, 95th, and 99th percentile values for latency-sensitive operations; mean values alone can mask high tail latency that affects application responsiveness.

### Event Verbosity Configuration and Performance Trade-offs

OpenArmor's event collection is configurable across a spectrum from minimal (process creation and network connections only) to comprehensive (all monitored event categories at maximum granularity). The performance characteristics described above reflect the default configuration, which is designed to balance comprehensive security coverage with acceptable overhead for typical enterprise workloads.

Organizations that require additional performance headroom can reduce verbosity selectively:

**File System Events:** The file system filter driver is the highest-volume event source on most systems. Verbosity can be reduced by:
- Restricting monitored file extensions (e.g., monitoring only executable, script, and document types rather than all file types)
- Excluding high-IOPS directories that are not security-relevant (e.g., database transaction log directories, CDN cache directories, build artifact output directories)
- Setting minimum file size thresholds for read monitoring to exclude trivial read operations

**Registry Events:** Registry monitoring verbosity can be reduced by:
- Limiting monitoring to security-sensitive key paths (autorun locations, security policy keys, service configuration) rather than the full registry tree
- Excluding HKCU hive subtrees for high-frequency application preference writes that are not security-relevant

**Network Events:** Network event granularity can be tuned by:
- Filtering by destination port to suppress monitoring of high-volume, low-risk traffic (e.g., DNS port 53 for internal resolvers, HTTPS port 443 for known-good corporate applications)
- Setting minimum connection duration thresholds to exclude very short-lived connections

All verbosity configuration changes involve a trade-off between performance overhead and detection coverage. Configuration changes that exclude event categories should be reviewed against the MITRE ATT&CK techniques detected by those categories to ensure that coverage gaps introduced by performance tuning are understood and accepted by the security team.

---

## Compliance and Regulatory Alignment

OpenArmor's endpoint monitoring capabilities directly support compliance with several major regulatory frameworks and security standards. The following alignment guidance is provided to assist compliance teams in mapping OpenArmor controls to their applicable frameworks.

### NIST Cybersecurity Framework (CSF) 2.0

OpenArmor contributes to multiple CSF 2.0 functions:

| CSF Function | Category | OpenArmor Contribution |
|---|---|---|
| **Identify (ID)** | Asset Management (ID.AM) | Endpoint inventory via agent registration; process and software inventory via image load events |
| **Protect (PR)** | Protective Technology (PR.PT) | File integrity monitoring; registry protection; driver-level self-protection |
| **Detect (DE)** | Anomalies and Events (DE.AE) | Continuous behavioral event collection; policy-based alert generation |
| **Detect (DE)** | Security Continuous Monitoring (DE.CM) | Kernel-level real-time monitoring of all endpoint event categories |
| **Respond (RS)** | Analysis (RS.AN) | Complete forensic event timeline for incident analysis |
| **Respond (RS)** | Mitigation (RS.MI) | Process termination capability via edrcon; integration with SOAR for automated response |
| **Recover (RC)** | Recovery Planning (RC.RP) | Event timeline provides complete attack reconstruction for recovery planning |

### CIS Controls v8

OpenArmor directly implements or contributes to the following CIS Controls:

- **Control 1 (Inventory of Enterprise Assets):** Agent deployment tracking provides endpoint inventory
- **Control 2 (Inventory of Software Assets):** Image load events provide per-endpoint software inventory
- **Control 8 (Audit Log Management):** Centralized, tamper-resistant event collection and retention
- **Control 10 (Malware Defenses):** Behavioral detection complementing signature-based antivirus
- **Control 13 (Network Monitoring and Defense):** Per-process network connection monitoring
- **Control 17 (Incident Response Management):** Complete forensic timeline for IR investigations

### PCI DSS v4.0

For organizations in the payment card industry, OpenArmor supports compliance with:

- **Requirement 10 (Log and Monitor All Access):** Comprehensive audit logging of all endpoint activity with tamper-evident storage in Elasticsearch
- **Requirement 11.5 (Detect and Report on Unauthorized File Changes):** File integrity monitoring for in-scope system components
- **Requirement 12.10 (Implement an Incident Response Plan):** Forensic timeline capability supporting PCI-required IR procedures

### HIPAA Security Rule

Healthcare organizations subject to HIPAA will find OpenArmor relevant to:

- **§164.312(b) — Audit Controls:** Comprehensive audit logging of access to systems that store, process, or transmit ePHI
- **§164.312(c)(1) — Integrity Controls:** File integrity monitoring for systems containing ePHI
- **§164.308(a)(6) — Security Incident Procedures:** Incident detection and forensic timeline for breach investigation

---

## Threat Intelligence Integration

OpenArmor is designed to consume and apply external threat intelligence to enrich its event stream and enhance detection coverage. Threat intelligence integration operates at multiple points in the event pipeline.

### Indicator of Compromise (IOC) Matching

The OpenArmor policy engine supports IOC matching against configurable indicator lists:

- **File hash lists:** SHA-256 hashes of known-malicious executables are matched against image load events. When a monitored process loads an image whose hash matches the IOC list, an alert is generated immediately with the full process context.
- **Domain lists:** Known-malicious domain names are matched against DNS query events captured by the network monitoring subsystem. Matches generate alerts with the querying process identified.
- **IP address lists:** Known-malicious IP addresses are matched against network connection events. Both source and destination IPs are checked; inbound connections from known-malicious sources are alerted alongside outbound connections.
- **File path patterns:** Suspicious file path patterns (e.g., executables in user-writable directories, scripts in system directories) are matched against file creation and image load events.

IOC lists are stored in configurable file paths and can be updated dynamically — the policy engine reloads indicator lists on a configurable interval without requiring agent restart. This supports automated IOC feed integration: threat intelligence platforms can write updated IOC lists to the configured paths on a schedule, and the agent picks up the updates within the next reload cycle.

### STIX/TAXII Integration

For organizations operating threat intelligence platforms that publish STIX 2.1 indicators over TAXII 2.1 feeds, a reference integration pipeline is provided in the `integrations/` directory that:

1. Polls configured TAXII collection endpoints on a scheduled interval
2. Extracts file hash, domain, and IP indicators from STIX bundles
3. Formats and writes updated IOC lists to the paths monitored by the OpenArmor policy engine
4. Logs indicator update operations for audit purposes

This integration supports platforms including MISP, OpenCTI, ThreatConnect, Anomali ThreatStream, and any TAXII 2.1-compliant feed.

### Threat Intelligence Enrichment in the Event Pipeline

The Logstash pipeline configuration provided in `integrations/elk/` includes enrichment stages that add threat intelligence context to events before they are indexed in Elasticsearch:

- **IP reputation lookup:** Outbound connection destination IPs are enriched with MaxMind GeoIP data (country, ASN, organization) and optionally with commercial IP reputation scores
- **Domain categorization:** DNS query events are enriched with domain age (from WHOIS data where available) and category classification
- **Process reputation:** Known-good process hashes can be used to suppress false positives; known-bad hashes trigger immediate alert enrichment

Enriched events carry additional fields (`threat_intel.*`) that can be used in Kibana visualizations, alert conditions, and investigation queries without modifying the core OpenArmor agent configuration.

---

## Project Governance and Development Standards

OpenArmor maintains enterprise-quality development standards consistent with production security tooling. The following governance practices apply to the project.

### Code Quality Standards

All contributions to OpenArmor core components (agent, kernel driver, libraries) must meet the following standards before merging:

- **Language standard:** C++17 conformance required; compiler extensions must not be used without explicit justification
- **Static analysis:** Code must pass analysis with the configured static analysis ruleset (configuration in `.editorconfig` and Visual Studio analysis settings)
- **Unit test coverage:** New functionality must include unit tests achieving a minimum of eighty percent line coverage
- **Reference tests:** Integration-level reference tests must pass without modification for all existing functionality
- **Memory safety:** Heap allocations must be managed through RAII patterns; raw `new`/`delete` pairs are not permitted in new code without explicit review justification
- **Error handling:** All system call return values must be checked; all exception paths must be documented

### Release Process

OpenArmor follows semantic versioning (MAJOR.MINOR.PATCH) with the following release cadence:

- **Patch releases:** Security fixes and critical bug fixes; target: within seventy-two hours of issue identification
- **Minor releases:** New features and non-breaking enhancements; target: quarterly
- **Major releases:** Breaking changes to configuration format, event schema, or driver interface; target: annually with minimum six-month deprecation notice for removed features

Each release includes:
- A signed binary distribution for the agent components
- Signed MSI installers for enterprise deployment
- Release notes documenting all changes with CVE references where applicable
- Updated documentation reflecting any configuration or schema changes
- Migration guide for any breaking changes

### Security Disclosure Policy

OpenArmor follows a responsible disclosure process for security vulnerabilities. Researchers who identify vulnerabilities in OpenArmor components should report them via the private security disclosure channel described in `SECURITY.md`. The project commits to:

- Acknowledging receipt of vulnerability reports within forty-eight hours
- Providing an initial severity assessment within five business days
- Releasing a patch within thirty days for critical and high severity vulnerabilities
- Coordinating public disclosure timing with the reporting researcher
- Providing credit to researchers who follow the disclosure process in the release notes for the fixing release

Vulnerabilities in third-party dependencies (including the AWS SDK for C++, OpenSSL, and other bundled libraries) are tracked and remediated following the upstream project's patch schedule. The project maintains a Software Bill of Materials (SBOM) listing all dependencies and their current versions, enabling downstream users to assess their exposure to newly disclosed vulnerabilities in dependencies.

# Section 2: Architecture & Component Reference

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Privilege Boundary Architecture](#privilege-boundary-architecture)
- [Thread Model & Concurrency](#thread-model--concurrency)
- [Object Model (libcore)](#object-model-libcore)
- [Component Reference](#component-reference)
  - [edrdrv — Kernel Driver](#edrdrv--kernel-driver)
  - [edrpm — Injected Process Monitor DLL](#edrpm--injected-process-monitor-dll)
  - [edrsvc — Windows Service](#edrsvc--windows-service)
  - [libsysmon — System Monitor](#libsysmon--system-monitor)
  - [libprocmon — Process Monitor Controller](#libprocmon--process-monitor-controller)
  - [libnetmon — Network Monitor](#libnetmon--network-monitor)
  - [libsyswin — Windows System Abstraction](#libsyswin--windows-system-abstraction)
  - [libedr — EDR Core Logic](#libedr--edr-core-logic)
  - [libcloud — Cloud Integration](#libcloud--cloud-integration)
  - [libcore — Core Framework](#libcore--core-framework)
  - [edrcon — Control Utility](#edrcon--control-utility)
  - [edrmm — Memory Manager](#edrmm--memory-manager)
  - [edrext — Extensions / System Info](#edrext--extensions--system-info)
  - [edrdata — Data & Scenarios](#edrdata--data--scenarios)

---

## Architecture Overview

<picture>
  <source srcset="assets/Technical_architecture_diagram_l…_202605010255.avif" type="image/avif">
  <img src="assets/Technical_architecture_diagram_l…_202605010255.avif" alt="OpenArmor technical architecture" width="100%">
</picture>

OpenArmor is a full-stack Windows Endpoint Detection and Response (EDR) platform constructed in C++17. Its design spans from ring-0 kernel operations down through a structured user-mode service layer and outward to cloud-connected threat intelligence and policy management. The architecture follows strict separation of concerns: telemetry collection is isolated at the kernel level, event transport is handled by a dedicated communication channel, and all detection, enrichment, and response logic runs in a structured pipeline within the Windows service process.

The following ASCII diagram illustrates the complete system topology, from the lowest kernel subsystems through the user-mode pipeline and out to cloud endpoints:

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                              KERNEL MODE (Ring 0)                                    ║
║                                                                                      ║
║  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  ║
║  │  Minifilter │  │ procmon  │  │  regmon  │  │  netmon      │  │ Self-Protect  │  ║
║  │  (filemon)  │  │          │  │          │  │  (WFP/nfwfp) │  │               │  ║
║  │ FltRegFilter│  │PsSetCreate│  │CmRegister│  │FwpmCalloutReg│  │ObRegisterCBs  │  ║
║  │ IRP hooks   │  │ NotifyEx  │  │ Callback │  │TCP/UDP/DNS   │  │Handle restrict│  ║
║  └──────┬──────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └───────────────┘  ║
║         │              │              │                │                              ║
║  ┌──────┴──────────────┴──────────────┴────────────────┴──────────────────────────┐  ║
║  │                          edrdrv.sys — DLL Injector                              │  ║
║  │               (kernel-mode injection of edrpm.dll into every new process)       │  ║
║  └──────────────────────────────────────┬──────────────────────────────────────────┘  ║
║                                         │                                              ║
║  ┌──────────────────────────────────────┴──────────────────────────────────────────┐  ║
║  │                   FltCreateCommunicationPort (FilterPort)                        │  ║
║  │              Async overlapped I/O — zero-copy kernel→user message bus            │  ║
║  └──────────────────────────────────────┬──────────────────────────────────────────┘  ║
╚════════════════════════════════════════ │ ════════════════════════════════════════════╝
                                          │
╔════════════════════════════════════════ │ ════════════════════════════════════════════╗
║                         USER MODE (Ring 3)                                            ║
║                                         │                                              ║
║  ┌───────────────────────────────────── │ ──────────────────────────────────────────┐ ║
║  │                    edrsvc.exe — Windows Service Host                               │ ║
║  │                                                                                    │ ║
║  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                            │ ║
║  │  │  libsysmon   │  │  libprocmon  │  │  libnetmon   │                            │ ║
║  │  │ FltPortRecvr │  │ ProcMon Rcvr │  │ NetMon Rcvr  │                            │ ║
║  │  │ 2 worker thds│  │ 2 worker thds│  │ 2 worker thds│                            │ ║
║  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                            │ ║
║  │         │                 │                  │                                     │ ║
║  │  ┌──────┴─────────────────┴──────────────────┴──────────────────────────────────┐ │ ║
║  │  │                   Queue Manager (libedr lane system)                           │ │ ║
║  │  │            Fast Lane │ SlowLocalFS Lane │ SlowNetwork Lane                     │ │ ║
║  │  └──────────────────────────────────┬───────────────────────────────────────────┘ │ ║
║  │                                     │                                              │ ║
║  │  ┌──────────────────────────────────┴───────────────────────────────────────────┐ │ ║
║  │  │                      QSC Pipeline (edrdata scenarios)                          │ │ ║
║  │  │                                                                                │ │ ║
║  │  │  [1] filter_lle  →  [2] enrich_lle  →  [3] match_patterns                     │ │ ║
║  │  │       ↓                    ↓                    ↓                              │ │ ║
║  │  │  [4] apply_policy  →  [5] get_fls_verdict  →  [6] check_for_valkyrie           │ │ ║
║  │  │       ↓                    ↓                    ↓                              │ │ ║
║  │  │  [7] output (alert/block/log/cloud upload)                                     │ │ ║
║  │  └──────────────────────────────────┬───────────────────────────────────────────┘ │ ║
║  │                                     │                                              │ ║
║  │  ┌──────────────────────────────────┴───────────────────────────────────────────┐ │ ║
║  │  │                    libcloud — Cloud Integration                                │ │ ║
║  │  │         AWS Firehose │ FLS (File List Service) │ GCP │ REST Policy API         │ │ ║
║  │  └──────────────────────────────────────────────────────────────────────────────┘ │ ║
║  └────────────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                         ║
║  ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║  │   edrpm.dll (injected into EVERY user-mode process via kernel DLL injector)      │   ║
║  │                                                                                   │   ║
║  │  Clipboard hooks │ Keyboard hooks │ Mouse hooks │ Screen capture │ Audio hooks   │   ║
║  │  Window hooks (SetWindowsHookEx) │ Thread impersonation │ Raw disk access        │   ║
║  │  Worker thread → event deduplication → FltPort → libprocmon                     │   ║
║  └─────────────────────────────────────────────────────────────────────────────────┘   ║
╚═════════════════════════════════════════════════════════════════════════════════════════╝
```

### Kernel Layer

The kernel layer of OpenArmor is implemented entirely within `edrdrv.sys`, a Windows kernel-mode driver that registers multiple monitoring subsystems against well-defined Windows kernel extension points. The minifilter component uses the Filter Manager framework (`FltRegisterFilter`, `FltStartFiltering`) to intercept file system I/O at the IRP level, observing create, write, rename, and delete operations across all file system volumes attached to the system without the fragility of legacy legacy filesystem filter drivers. The process monitor attaches via `PsSetCreateProcessNotifyRoutineEx`, receiving structured notification records for every process creation and termination system-wide. The registry monitor uses `CmRegisterCallback` to intercept key and value operations before they are committed to the hive. The network monitor leverages the Windows Filtering Platform (WFP) through an integrated callout driver, capturing TCP connection establishment, UDP datagrams, and DNS query traffic at the network stack level. All subsystems funnel their structured event records into a shared FilterPort communication channel.

Self-protection within the kernel driver ensures that the agent cannot be trivially disabled by a threat actor operating at user-mode privilege level. This is achieved through object callback registration (`ObRegisterCallbacks`) which intercepts handle creation and duplication requests targeting the agent's own process and threads, stripping dangerous access rights such as `PROCESS_TERMINATE` and `PROCESS_VM_WRITE`. The driver's own device object, symbolic links, and associated registry keys are protected by mandatory access control entries that reject modification even from Administrator-level processes. The DLL injection subsystem operates as a kernel-mode component that receives new process creation notifications and maps `edrpm.dll` into the target process address space before user-mode code begins executing, ensuring that every process is instrumented from its very first instruction.

### Communication Channel

The FilterPort (`FltCreateCommunicationPort`) provides the primary conduit between the kernel driver and the user-mode service. This mechanism, native to the Windows Filter Manager, is specifically designed for high-throughput, low-latency kernel-to-user event delivery. Unlike traditional IOCTL-based communication, the FilterPort supports asynchronous overlapped I/O on the user-mode side, allowing a small pool of receiver threads to drain large volumes of kernel events without blocking. Messages are serialized in LBVS (Length-Based Value Serialization) binary format within the kernel, eliminating JSON parsing overhead on the hot path. A separate IOCTL dispatch interface is maintained for control operations such as policy updates, protection configuration changes, and driver state queries, which are initiated from user mode toward the kernel.

### User-Mode Pipeline

Within `edrsvc.exe`, incoming events from all three kernel subsystems are received by their respective library components (`libsysmon`, `libprocmon`, `libnetmon`), each operating with dedicated receiver thread pairs. Raw events, called Low-Level Events (LLEs), are placed into the Queue Manager which implements a three-lane priority system. The QSC (Query Scenario Configuration) pipeline then processes each event through a sequence of structured stages: initial filtering, contextual enrichment using process and file metadata, behavioral pattern matching against compiled policy rules, policy application to determine response action, cloud-based file reputation lookup via the File List Service (FLS), secondary validation through the Valkyrie sandbox verdict service, and finally output routing to alert streams, response actions, and cloud telemetry upload.

---

## Privilege Boundary Architecture

Windows imposes a hard boundary between kernel mode (ring 0) and user mode (ring 3). Code executing in kernel mode has unrestricted access to system resources, hardware, and the kernel object graph. User-mode code operates within a protected address space isolated from other processes and from the kernel itself. OpenArmor's architecture deliberately separates telemetry collection into the kernel and all detection logic into user mode, following the principle of minimal kernel footprint. Only the code that absolutely requires kernel privilege — file system interception, process creation notification, registry monitoring, and network filtering — runs in the driver. Detection algorithms, policy evaluation, enrichment lookups, and cloud communication all run at user-mode privilege, reducing the blast radius of any software defect.

### FilterPort Communication

The Filter Manager's `FltCreateCommunicationPort` API creates a named kernel port object that is accessible to a specific user-mode process via a handle returned by `FilterConnectCommunicationPort`. This model provides several critical security properties. First, the port name is governed by a Security Descriptor set at port creation time, ensuring that only the service process (running as LocalSystem) can connect. Second, communication is asymmetric: the kernel driver initiates pushes of event data via `FltSendMessage`, while the user-mode process can also send control messages via `FilterSendMessage`. Third, the channel supports asynchronous overlapped I/O on the user-mode side — each receiver thread issues a `GetQueuedCompletionStatus` call against a completion port associated with the filter port handle, allowing a single thread to service multiple in-flight receive buffers without blocking on any single message. Buffer sizes are dynamically adjusted from a minimum of 4 KB (sufficient for a single serialized event) up to 1 MB (for burst absorption during high-activity periods), amortizing system-call overhead across large batches.

### IOCTL Interface

The network monitor component (`netmon`) operates partially through the Windows Filtering Platform callout model and partially through a traditional device object exposed by the driver at `\Device\edrdrv`. Control operations — such as enabling or disabling network monitoring, updating DNS filter lists, and retrieving connection table snapshots — are communicated from user mode via `DeviceIoControl` calls against this device object. The driver's `IRP_MJ_DEVICE_CONTROL` dispatch routine validates the calling process identity against the service process token before processing any control request. Input and output buffers are validated for minimum length and proper alignment before any kernel-mode pointer arithmetic is performed, guarding against information disclosure and kernel memory corruption.

### Security Model

The communication channel is secured at multiple layers. At the FilterPort level, the Security Descriptor grants `FILE_ALL_ACCESS` exclusively to the `NT AUTHORITY\SYSTEM` SID, matching the identity under which `edrsvc.exe` runs. The driver enforces that only one user-mode client can connect to each port simultaneously, preventing a rogue process from stealing the connection. For the IOCTL interface, the device object's Security Descriptor restricts access to `SYSTEM` and members of the `Builtin\Administrators` group for read-only status queries. Any message received over the FilterPort from user mode (sent via `FilterSendMessage`) is treated as an untrusted control request and is validated against a whitelist of recognized command identifiers and expected payload sizes before any kernel action is taken. This design ensures that even a fully compromised user-mode process cannot send arbitrary kernel commands.

---

## Thread Model & Concurrency

OpenArmor's concurrency architecture is carefully engineered to maximize event throughput while maintaining bounded latency for high-priority detections. The thread model is hierarchical: a small set of dedicated I/O threads drain kernel events as fast as the hardware allows, handing off to a structured ThreadPool for CPU-bound processing. All shared state is protected by a well-defined lock hierarchy that eliminates deadlock risk under any execution order.

### Service Main Thread

The service main thread is responsible for Windows Service Control Manager (SCM) integration. It enters the `ServiceMain` entry point registered with the SCM, processes control codes (`SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_PAUSE`, `SERVICE_CONTROL_INTERROGATE`), and manages the overall application lifecycle. During startup, the main thread initializes the ObjectManager registry, instantiates all `IService` implementations from the Catalog, sequentially calls their `start()` methods in dependency order, and then publishes the `AppStarted` message to the message bus. During shutdown, it publishes `AppFinishing`, waits for all services to complete their `stop()` sequences, and then calls `shutdown()` on each. The main thread does not perform any event processing; all telemetry handling is delegated to dedicated worker threads.

### FilterPort Receiver Threads

Each kernel subsystem that communicates via FilterPort is serviced by exactly two dedicated receiver threads. The two-thread model provides a degree of pipelining: while one thread is in the kernel servicing a `GetQueuedCompletionStatus` call, the other can be deserializing and enqueueing the previously received message buffer. Each thread holds a pre-allocated receive buffer and an OVERLAPPED structure registered with the service process's I/O Completion Port. Upon receiving a message, the thread deserializes the LBVS binary payload into a `Variant` dictionary representing the raw Low-Level Event (LLE), then places the event into the appropriate lane of the Queue Manager before returning to wait for the next message. With two threads per subsystem and three subsystems (`libsysmon`, `libprocmon`, `libnetmon`), there are six FilterPort receiver threads operating concurrently at steady state. These threads are given `THREAD_PRIORITY_ABOVE_NORMAL` to minimize event loss during burst conditions.

### ThreadPool for Async Command Execution

The ThreadPool (implemented in `libcore`) provides a fixed-size pool of worker threads for executing `ICommand` instances submitted by the QSC pipeline and by service components. The pool size is configurable and defaults to `2 × NumberOfLogicalProcessors`, capped at a practical maximum to avoid thread context-switch overhead on high-core-count systems. Commands are submitted via a lock-free MPMC queue. Each worker thread blocks on a semaphore and is signaled when a command is enqueued. Commands encapsulate a unit of work — such as processing a batch of LLEs through the pipeline, uploading a telemetry batch to the cloud, or executing a policy recompilation — along with any input `Variant` data they require. Long-running commands (e.g., hash computation on large files) release the worker thread between checkpoints to avoid starving the pool.

### Lane System: Fast, SlowLocalFS, SlowNetwork

The Queue Manager implements a three-lane system that segregates events based on their expected processing latency profile. This is essential for preventing slow I/O operations — such as hash computation on a large file or a DNS reverse lookup — from blocking the processing of time-critical process creation events.

| Lane | Intended Events | Blocking Operations Allowed | Thread Priority |
|---|---|---|---|
| Fast | Process create/terminate, registry events | None — must complete in microseconds | Above Normal |
| SlowLocalFS | File create/write/rename/delete with hash computation | Local disk I/O, PE header parsing | Normal |
| SlowNetwork | Network connection events requiring DNS resolution or FLS verdict | Network I/O, cloud API calls | Below Normal |

Each lane is backed by its own bounded queue and its own dedicated ThreadPool partition. When a pipeline stage detects that it needs to perform a slow operation but the current event is being processed on the Fast lane, it raises a `SlowLaneOperation` exception. The Queue Manager catches this exception, re-enqueues the event to the appropriate slower lane, and the Fast lane thread immediately returns to processing the next event. This prevents priority inversion and ensures that process monitoring events — which are the most time-sensitive for blocking detections — are never delayed by file hashing or network lookups. The lane assignment of each event is tracked per-thread via a thread-local variable, and the helper function `checkCurLane()` is called at the entry point of every potentially slow operation to validate that the caller is on an acceptable lane before proceeding.

### Lock Hierarchy

To eliminate deadlock risk, OpenArmor defines a strict global lock ordering. Locks must always be acquired in the following order, and must never be acquired in reverse:

1. ObjectManager registry lock (coarse-grained, rarely held)
2. Service Catalog lock (per-service state mutex)
3. Queue Manager lane locks (per-lane mutex protecting queue head/tail)
4. Event deduplication table lock (per-subsystem hash table mutex)
5. Variant internal lock (fine-grained, held only during mutation)

No code path acquires a lock of a lower ordinal while holding a lock of a higher ordinal. Code review guidelines enforce this via static analysis annotations. Reader-writer locks (`std::shared_mutex`) are used for the process information cache (high read, low write ratio) and the signature verification cache (effectively read-only after initial population), reducing contention significantly in the common case.

---

## Object Model (libcore)

The `libcore` library provides the foundational object model upon which every other component in OpenArmor is built. It defines the base interfaces, the factory registry, the service lifecycle contract, the universal data container, and the message bus. Understanding `libcore` is a prerequisite for understanding every other component.

### `IObject` and `ObjPtr<T>`

`IObject` is the root interface of the OpenArmor type system. It is a pure abstract class providing reference counting semantics via `addRef()` and `release()` methods. All concrete objects in the system inherit from `IObject`, either directly or through a more specialized interface. `ObjPtr<T>` is the smart pointer template that wraps any `IObject`-derived type, calling `addRef()` on copy and `release()` on destruction. It supports implicit construction from raw pointers returned by factory functions and provides `get()`, `operator->()`, and `operator bool()`. Unlike `std::shared_ptr`, `ObjPtr<T>` is intrusive: the reference count lives inside the object itself, eliminating the separate control block allocation and improving cache locality when many pointers to the same object exist. `ObjPtr<T>` is not thread-safe for concurrent mutation of the same pointer instance, but the reference count itself is manipulated with atomic operations, making shared ownership across threads safe as long as each thread holds its own `ObjPtr<T>` instance.

### `ObjectManager` — Factory and Registry

`ObjectManager` is the central factory registry for all component types in the system. It maintains a global map from `ClassId` (a 64-bit hash of the class name string) to a factory function. Components register their factory functions at static initialization time via a registration macro. At runtime, any component can call `ObjectManager::createObject(ClassId, params)` to instantiate any registered type by identifier, without taking a compile-time dependency on the concrete implementation. This enables a plugin-like architecture where components can be replaced or extended without modifying callers. The `ObjectManager` also maintains the singleton catalog of active `IService` instances and provides the `createService(ClassId)` and `findService(ClassId)` operations used during service startup. Factory functions receive a `Variant` parameter block containing construction-time configuration, allowing type-specific initialization to be driven entirely from JSON configuration files.

### `IService` — Lifecycle Contract

`IService` extends `IObject` with a standardized lifecycle that every service component must implement:

| Method | Called When | Semantics |
|---|---|---|
| `loadState(Variant cfg)` | Startup, before `start()` | Load persisted state, apply configuration |
| `start()` | Startup, after all `loadState()` calls | Begin active operation, spawn threads |
| `stop()` | Shutdown, before `shutdown()` | Signal threads to exit, drain queues |
| `saveState()` | Shutdown, after `stop()` | Persist state to disk for next run |
| `shutdown()` | Shutdown, final | Release all resources |

Services are started in dependency order as resolved by the Catalog. The Catalog is an `ObjectManager`-managed singleton that services register with via `ICatalog::registerService()`. Dependencies are declared via `ICatalog::requireService(ClassId)`. The Catalog performs a topological sort of declared dependencies and starts services in the resulting order, failing fast if a circular dependency is detected. This ensures, for example, that `libcloud` is fully operational before `libedr` attempts to push policy-triggered cloud verdicts.

### `Variant` — Universal Data Container

`Variant` is OpenArmor's polymorphic data container, functionally analogous to a JSON value but with additional binary and type-extension capabilities. It is the universal currency for data exchange between all components: LLE events, policy rule definitions, configuration blocks, cloud API payloads, and IPC messages are all represented as `Variant` instances.

Supported types:

| Type Tag | C++ Representation | Notes |
|---|---|---|
| `Dictionary` | `std::map<std::string, Variant>` | Key-value map, JSON object equivalent |
| `Sequence` | `std::vector<Variant>` | Ordered list, JSON array equivalent |
| `Integer` | `int64_t` | Signed 64-bit; also covers boolean internally |
| `String` | `std::string` | UTF-8 |
| `Boolean` | `bool` | Distinct tag from Integer for serialization |
| `Binary` | `std::vector<uint8_t>` | Arbitrary byte sequence, not JSON-serializable |
| `Null` | — | Absence of value |

`Variant` supports JSON serialization/deserialization via `jsoncpp` for configuration files and cloud payloads, and LBVS (Length-Based Value Serialization) binary encoding for high-performance kernel-to-user event transport. LBVS encodes each field as a type-byte followed by a 4-byte length prefix and the value bytes, enabling zero-copy parsing: a receiver can walk the buffer in a single linear pass without any heap allocation for fixed-size types. `Variant` provides a rich accessor API: `get<T>(key)`, `getAt<T>(index)`, `put(key, value)`, `append(value)`, `contains(key)`, and `size()`. Dictionary access is case-sensitive and ordered, matching JSON semantics. Variant instances are reference-counted when they contain heap-allocated data (Dictionaries, Sequences, Strings, Binaries) and value-copied for scalar types.

### `IDataReceiver` / `IDataProvider`

These two interfaces define the event source/sink abstraction used throughout the pipeline. `IDataProvider` exposes a `subscribe(ObjPtr<IDataReceiver>)` method; any number of receivers can subscribe to a single provider. `IDataReceiver` exposes a single `put(Variant data)` method which is called by the provider for each event. This pull/push hybrid model allows the pipeline to be assembled as a chain of processing stages, each of which is both a receiver (consuming events from the upstream stage) and a provider (publishing transformed events to downstream subscribers). The QSC pipeline stages implement this interface, as do the `libsysmon`, `libprocmon`, and `libnetmon` event sources. Subscription relationships are configured at service startup time based on the JSON pipeline definition in `edrdata`.

### `ICommand` / `ICommandProcessor`

The command pattern is used for all operations that must be dispatched asynchronously or that need to be retried, queued, or audited. `ICommand` is a simple interface with a single `execute()` method. `ICommandProcessor` receives commands via `processCommand(ObjPtr<ICommand>)` and is responsible for scheduling or directly executing them. Concrete implementations include the `ThreadPool` (which queues commands for worker thread execution), the `SerialCommandProcessor` (which executes commands in submission order on a single dedicated thread — used for cloud upload to maintain ordering guarantees), and the `RetryCommandProcessor` (which wraps another processor and re-submits failed commands with exponential backoff). Commands carry their input data as `Variant` fields and may carry output callbacks for result delivery.

### Message Bus

The message bus provides a publish-subscribe mechanism for loosely coupled coordination between services. Any component can call `subscribeToMessage(MessageId, ObjPtr<IDataReceiver>)` to register interest in a named system event. Any component can call `publishMessage(MessageId, Variant data)` to broadcast a named event to all subscribers. Message delivery is synchronous on the publishing thread, so subscribers must complete quickly or hand off work to a background thread. Predefined message identifiers:

| Message | Published By | Subscribers | Purpose |
|---|---|---|---|
| `AppStarted` | `edrsvc` main thread | All services | Signal that startup is complete; begin steady-state operation |
| `AppFinishing` | `edrsvc` main thread | All services | Signal imminent shutdown; drain queues and cease new work |
| `PolicyIsUpdated` | `libcloud` | `libedr`, `edrdata` | Trigger policy recompilation and pipeline reconfiguration |
| `CloudConfigurationIsChanged` | `libcloud` | `libcloud` itself, `libnetmon` | Apply new cloud endpoint URLs, credentials, or feature flags |

---

## Component Reference

The following subsections provide complete reference documentation for each of the thirteen primary components that make up the OpenArmor platform.

---

### edrdrv — Kernel Driver

<picture>
  <source srcset="assets/Windows_security_monitoring_laye…_202605010255.avif" type="image/avif">
  <img src="assets/Windows_security_monitoring_laye…_202605010255.avif" alt="Windows security monitoring layers" width="100%">
</picture>

#### Purpose

`edrdrv.sys` is the Windows kernel-mode driver that forms the sensing layer of the OpenArmor platform. It registers with multiple kernel extension points to observe every significant security-relevant system event — file operations, process lifecycle, registry mutations, and network connections — and delivers these events to the user-mode service with minimal latency and overhead. It also performs kernel-mode injection of `edrpm.dll` into every new process and enforces self-protection of the agent's own components.

#### Key Classes and Interfaces

| Component | Key Kernel API | Registration Point |
|---|---|---|
| Minifilter (filemon) | `FltRegisterFilter`, `FltStartFiltering` | Filter Manager altitude registration |
| Process monitor (procmon) | `PsSetCreateProcessNotifyRoutineEx` | Kernel process create/terminate callbacks |
| Registry monitor (regmon) | `CmRegisterCallback` | Configuration Manager callbacks |
| Network monitor (netmon) | WFP callout via `FwpmCalloutRegister` | Network stack at ALE and datagram layers |
| DLL injector (dllinj) | `ZwMapViewOfSection`, `KeInsertQueueApc` | Post-process-create APC queue |
| Self-protection | `ObRegisterCallbacks` | Object manager pre-operation callbacks |
| FilterPort | `FltCreateCommunicationPort` | Filter Manager port object |
| IOCTL dispatch | `IRP_MJ_DEVICE_CONTROL` handler | Device object dispatch table |

#### Minifilter (filemon)

The minifilter component registers at a specific altitude in the filter stack (above antivirus and below encryption drivers). It installs pre-operation callbacks for `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (for rename and delete), and post-operation callbacks for `IRP_MJ_CREATE` (to capture the final granted access). For each intercepted operation, the minifilter assembles a fixed-size event record containing: the normalized NT file path (converted from the filter's `FLT_FILE_NAME_INFORMATION`), the process ID, the thread ID, the operation type, the file size (where available), and a high-resolution timestamp from `KeQueryPerformanceCounter`. Records are placed into a kernel-mode ring buffer protected by a spin lock. A dedicated kernel thread drains this buffer and sends batches over the FilterPort to user mode.

Event filtering in the kernel is an important performance optimization: the driver maintains a per-extension and per-directory exclusion list (loaded from a policy pushed down by the user-mode service) and silently drops events that match exclusions before they are serialized. This significantly reduces the volume of events delivered to user mode for noisy but uninteresting paths such as browser cache directories and Windows temporary file locations.

#### Process Monitor (procmon)

`PsSetCreateProcessNotifyRoutineEx` delivers a `PS_CREATE_NOTIFY_INFO` structure to the driver callback for every process creation and termination event system-wide. The `procmon` component extracts the image file name, the command line, the parent process ID, and the creating thread ID. For process termination, it records the exit code. A deduplication filter discards repeated creation events for the same PID within a short window (100 ms), which can occur in certain process-hollowing scenarios where the loader reinitializes.

The `procmon` component is the highest-priority event source in the driver: process creation events are never dropped even under extreme memory pressure, because they are needed to maintain the process tree used by `libsyswin`'s `ProcessDataProvider`. A pre-allocated event pool (configurable size, default 512 records) is used to avoid any heap allocation on the process creation callback path, which executes at `IRQL == PASSIVE_LEVEL` but in a performance-critical context.

#### Registry Monitor (regmon)

`CmRegisterCallback` installs a `EX_CALLBACK_FUNCTION` that receives both pre- and post-operation notifications for all registry operations. The `regmon` component processes: `RegNtPreCreateKey`, `RegNtPreDeleteKey`, `RegNtPreSetValueKey`, `RegNtPreDeleteValueKey`, `RegNtPreRenameKey`, and their post-operation counterparts. For each event, the component resolves the registry key path from the `REG_CREATE_KEY_INFORMATION` or equivalent structure, converts abbreviated paths (such as those beginning with `\REGISTRY\MACHINE\`) to their canonical forms, and records the value name, value type, and value data (for set operations, up to a configurable size limit to avoid exfiltrating secrets from registry values).

The registry monitor is particularly important for detecting persistence mechanisms that write autorun keys, service registrations, and COM object hijacks. Performance filtering excludes high-frequency system paths (e.g., `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`) that generate noise without security relevance.

#### Network Monitor (netmon)

The network monitor integrates with the Windows Filtering Platform through `nfwfpdrv.lib`, a library that abstracts WFP callout registration and management. The driver registers callouts at the following WFP layers:

| WFP Layer | GUID | Events Captured |
|---|---|---|
| `FWPM_LAYER_ALE_CONNECT_V4` / `V6` | Connection establishment | TCP outbound connect, UDP send |
| `FWPM_LAYER_ALE_RECV_ACCEPT_V4` / `V6` | Inbound connection acceptance | TCP listen, inbound connect |
| `FWPM_LAYER_DATAGRAM_DATA_V4` | UDP datagram data | DNS queries (UDP port 53) |
| `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` | Flow establishment | Full 5-tuple recording |

For each connection event, the callout records: the local and remote IP addresses, local and remote ports, protocol (TCP/UDP), the process ID of the creating flow, and the flow direction. DNS events additionally capture the query name string extracted from the UDP datagram payload. All network events are forwarded through the FilterPort using the same LBVS binary encoding as file and process events.

#### DLL Injector (dllinj)

The DLL injector operates within the process create notify callback context. When a new process is created, the injector retrieves the base address of `ntdll.dll` from the process's PEB (Process Environment Block) to locate `LdrLoadDll`. It then queues a kernel APC (`KeInsertQueueApc`) to the first thread of the new process, scheduled to execute when the thread enters an alertable wait state. The APC routine maps `edrpm.dll` into the target process using `ZwMapViewOfSection` against a pre-created section object, then calls `LdrLoadDll` to complete the load. The target process ID and injection result are recorded for health monitoring. On 64-bit Windows, WoW64 processes receive a 32-bit `edrpm.dll` (from a parallel build), while 64-bit processes receive the 64-bit variant. The injector respects a configurable exclusion list of process image names that should not be instrumented (e.g., system processes that cannot tolerate DLL injection).

#### Self-Protection

Self-protection is implemented at three levels. First, `ObRegisterCallbacks` registers a pre-operation callback on `PsProcessType` and `PsThreadType` object types. Any attempt to open the `edrsvc.exe` process with `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME`, or `PROCESS_DUP_HANDLE` rights is intercepted and those rights are stripped from the requested access mask before the handle is granted. Second, the driver's image file and associated registry keys are protected by Kernel Transaction Manager-based file locks that prevent deletion or modification while the driver is loaded. Third, the driver refuses to unload (`DriverUnload` is set to NULL) once it has been started, ensuring that it cannot be removed without a system reboot even by a caller with `SeLoadDriverPrivilege`.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `filemon.enabled` | `true` | Enable file system monitoring |
| `filemon.exclusions` | System paths | Path prefixes to exclude from file events |
| `procmon.dedup_window_ms` | `100` | Process create dedup window in milliseconds |
| `regmon.enabled` | `true` | Enable registry monitoring |
| `regmon.exclusions` | System noise paths | Key prefixes to exclude from registry events |
| `netmon.enabled` | `true` | Enable network monitoring |
| `netmon.dns_capture` | `true` | Capture DNS query content |
| `dllinj.enabled` | `true` | Enable DLL injection into new processes |
| `dllinj.exclusions` | `[]` | Process image names to skip injection |
| `selfprot.enabled` | `true` | Enable self-protection |
| `filterport.buffer_size_min` | `4096` | Minimum receive buffer size (bytes) |
| `filterport.buffer_size_max` | `1048576` | Maximum receive buffer size (bytes) |

---

### edrpm — Injected Process Monitor DLL

<picture>
  <source srcset="assets/Tree_visualization_of_process_hi…_202605010255.avif" type="image/avif">
  <img src="assets/Tree_visualization_of_process_hi…_202605010255.avif" alt="Process hierarchy visualization" width="100%">
</picture>

#### Purpose

`edrpm.dll` is injected by the kernel driver into every new user-mode process on the system. Once loaded, it uses Microsoft Detours to intercept a defined set of Win32 API calls, monitoring for behaviors associated with data exfiltration, surveillance, lateral movement, and persistence. Intercepted API calls are serialized into structured event records and forwarded to `edrsvc.exe` via the FilterPort communication channel.

#### Key Classes and Interfaces

- `PmAgent`: singleton class initialized in `DllMain`, manages hook installation and the worker thread
- `HookManager`: installs and removes all Detours hooks; handles WoW64 thunk patching
- `EventQueue`: thread-safe ring buffer accumulating raw hook events before worker thread processing
- `EventDeduplicator`: suppresses repeated identical events within a configurable time window
- `FltPortClient`: wraps `FilterConnectCommunicationPort` and `FilterSendMessage` for event delivery

#### Hooked API Reference

The following table enumerates every API function intercepted by `edrpm.dll`, the event type generated, and the detection purpose:

| Category | Intercepted API | Event Generated | Detection Purpose |
|---|---|---|---|
| **Clipboard** | `GetClipboardData` | `PROCMON_API_GET_CLIPBOARD_DATA` | Detect clipboard content theft |
| **Clipboard** | `SetClipboardViewer` | `PROCMON_API_SET_CLIPBOARD_VIEWER` | Detect clipboard chain monitoring installation |
| **Clipboard** | `OpenClipboard` | `PROCMON_API_OPEN_CLIPBOARD` | Detect repeated clipboard access patterns |
| **Keyboard** | `GetKeyboardState` | `PROCMON_API_GET_KEYBOARD_STATE` | Detect keylogger state polling |
| **Keyboard** | `GetKeyState` | `PROCMON_API_GET_KEY_STATE` | Detect individual key state polling |
| **Keyboard** | `RegisterHotKey` | `PROCMON_API_REGISTER_HOT_KEY` | Detect global hotkey registration for keylogging |
| **Keyboard** | `BlockInput` | `PROCMON_API_BLOCK_INPUT` | Detect input blocking (ransomware lock screens) |
| **Keyboard** | `keybd_event` | `PROCMON_API_KEYBD_EVENT` | Detect synthetic keystroke injection |
| **Keyboard** | `SendInput` | `PROCMON_API_SEND_INPUT` | Detect automated input injection |
| **Mouse** | `mouse_event` | `PROCMON_API_MOUSE_EVENT` | Detect synthetic mouse event injection |
| **Mouse** | `ClipCursor` | `PROCMON_API_CLIP_CURSOR` | Detect cursor confinement (lock-screen attacks) |
| **Screen** | `BitBlt` (clipboard bitmap path) | `PROCMON_COPY_WINDOW_BITMAP` | Detect screen capture via GDI |
| **Screen** | `PrintWindow` | `PROCMON_COPY_WINDOW_BITMAP` | Detect per-window screen capture |
| **Screen** | Desktop wallpaper set APIs | `PROCMON_DESKTOP_WALLPAPER_SET` | Detect ransomware wallpaper replacement |
| **Audio** | `IMMDeviceEnumerator::EnumAudioEndpoints` | `PROCMON_API_ENUM_AUDIO_ENDPOINTS` | Detect microphone/speaker enumeration |
| **Audio** | `waveInOpen` | `PROCMON_API_WAVE_IN_OPEN` | Detect audio recording session open |
| **Window Hooks** | `SetWindowsHookEx` (all hook types) | `PROCMON_API_SET_WINDOWS_HOOK` | Detect global hook installation (keyloggers, shellcode injectors) |
| **Thread** | `ImpersonateLoggedOnUser` | `PROCMON_THREAD_IMPERSONATION` | Detect token impersonation for privilege escalation |
| **Thread** | `SetThreadToken` | `PROCMON_THREAD_IMPERSONATION` | Detect explicit thread token replacement |
| **Thread** | `ImpersonateNamedPipeClient` | `PROCMON_THREAD_IMPERSONATION` | Detect pipe-based impersonation |
| **Disk** | `CreateFile` on raw volume paths (`\\.\PhysicalDrive*`, `\\.\Volume*`) | `PROCMON_RAW_DISK_ACCESS` | Detect raw disk access for MBR manipulation or data recovery |
| **Injection Config** | Internal config push channel | `PROCMON_INJECTION_CONFIG_UPDATE` | Receive updated monitoring configuration from `edrsvc` |
| **Process Memory** | `ReadProcessMemory` | `PROCMON_PROCESS_MEMORY_READ` | Detect cross-process memory reading (credential dumping) |
| **Process Memory** | `WriteProcessMemory` | `PROCMON_PROCESS_MEMORY_WRITE` | Detect cross-process memory writing (code injection) |

#### Event Queue and Worker Thread

`edrpm.dll` maintains a lock-free single-producer single-consumer ring buffer (the `EventQueue`) within the address space of each instrumented process. Hook callbacks, executing on arbitrary application threads, write serialized event records into the queue with a single atomic compare-exchange operation. A dedicated worker thread, created during DLL initialization, drains the queue, applies deduplication logic, and dispatches events to the FilterPort client.

Deduplication operates on a timeout window (configurable, default 500 ms): if the same API is called with identical arguments from the same calling thread within the window, subsequent occurrences are counted but not individually forwarded. When the window expires, a single summary event carrying the call count is emitted. This is critical for APIs like `GetKeyState` which may be polled thousands of times per second by certain applications.

The FilterPort client within `edrpm.dll` connects to a named port exposed by the kernel driver (distinct from the main service FilterPort). If the connection is unavailable (e.g., driver not yet loaded, or the process is excluded), the DLL silently operates in a no-op mode without generating errors visible to the host application.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `edrpm.dedup_window_ms` | `500` | Deduplication window per API and thread |
| `edrpm.queue_depth` | `4096` | Ring buffer capacity (events) |
| `edrpm.worker_priority` | `THREAD_PRIORITY_NORMAL` | Worker thread scheduling priority |
| `edrpm.hook.clipboard` | `true` | Enable clipboard API hooks |
| `edrpm.hook.keyboard` | `true` | Enable keyboard API hooks |
| `edrpm.hook.screen` | `true` | Enable screen capture API hooks |
| `edrpm.hook.audio` | `true` | Enable audio API hooks |
| `edrpm.hook.process_memory` | `true` | Enable process memory R/W hooks |
| `edrpm.hook.raw_disk` | `true` | Enable raw disk access hooks |
| `edrpm.hook.window_hooks` | `true` | Enable `SetWindowsHookEx` interception |

---

### edrsvc — Windows Service

#### Purpose

`edrsvc.exe` is the Windows service host process for all user-mode OpenArmor components. It integrates with the Windows Service Control Manager, manages the full component lifecycle, loads configuration, initializes the ObjectManager registry, and provides the RPC interface for administrative operations. It is the single process that all user-mode libraries run within.

#### Key Classes and Interfaces

- `WinService`: wraps `StartServiceCtrlDispatcher`, `RegisterServiceCtrlHandlerEx`, `SetServiceStatus`; delegates control codes to the Application object
- `Application`: owns the ObjectManager, Catalog, and all `IService` instances; coordinates startup and shutdown sequences
- `ConfigLoader`: reads JSON configuration from the installation directory, applies command-line overrides, and provides the resulting `Variant` tree to the ObjectManager
- `RpcServer`: exposes an RPC endpoint over a local named pipe for `edrcon` to issue administrative commands
- `ElevationHelper`: re-launches a sub-process with elevated token for operations requiring `SeDebugPrivilege` or similar

#### Application Modes

`edrsvc.exe` supports several operational modes selected by command-line arguments:

| Mode | Argument | Description |
|---|---|---|
| Run (foreground) | `run` | Run as a regular process (for debugging); no SCM integration |
| Service start | `start` | Start the service via SCM |
| Service stop | `stop` | Stop the service via SCM |
| Install | `install` | Register the service with SCM; install the kernel driver |
| Enroll | `enroll` | Enroll this endpoint with the cloud management console |
| Wait | `wait` | Block until the service reaches a target state |
| Dump | `dump` | Dump current agent state to a structured JSON file |

#### Configuration Loading

Configuration is loaded from `config.json` in the agent's installation directory. The format is a nested JSON object corresponding to the `Variant` dictionary structure consumed by each component's `loadState()` method. Command-line arguments of the form `--key.subkey=value` override individual fields in the loaded configuration, supporting per-deployment customization without modifying the base configuration file. The resulting configuration tree is provided to the ObjectManager before any service is started, ensuring that all components receive their configuration before `start()` is called.

#### Operational Characteristics

The service runs under the `LocalSystem` account, which provides the necessary privileges for FilterPort connection, kernel driver communication, and process token inspection. A dedicated security descriptor on the service registration restricts SCM stop/pause operations to members of the local `Administrators` group, preventing non-elevated users from disabling protection. The RPC named pipe is ACL'd to `Administrators` and `SYSTEM` only. UAC elevation for operations such as `unprot` (temporarily disabling self-protection) is performed by the RPC server relaunching a privileged subprocess, rather than running the entire service at elevated integrity level.

---

### libsysmon — System Monitor

#### Purpose

`libsysmon` is the user-mode library responsible for receiving file system, process, and registry events from the kernel driver via the FilterPort channel. It abstracts the low-level mechanics of overlapped I/O and LBVS deserialization, presenting a clean `IDataProvider` interface to the rest of the pipeline.

#### Key Classes and Interfaces

- `FltPortReceiver`: manages the FilterPort connection, two overlapped receive buffers, and the I/O Completion Port
- `LbvsDeserializer`: walks a raw LBVS buffer, producing a `Variant` dictionary for each encoded event record
- `SysmonEventSource`: implements `IDataProvider`, dispatching deserialized events to registered `IDataReceiver` subscribers

#### I/O Model

`FltPortReceiver` maintains two active overlapped I/O requests at all times, forming a double-buffer: while the kernel is filling buffer A, the user-mode worker thread is deserializing buffer B. When buffer A completes, the worker posts a new receive on it while switching to deserialize B. This ensures that the kernel never waits for the user-mode thread to be ready; the pending receive is always available. Buffer sizes start at 4 KB and are dynamically increased (up to 1 MB) when the receiver detects that kernel batches are saturating the full buffer, which indicates that the kernel is queueing events faster than user mode can drain them.

#### Event Types Produced

| Event Type | Trigger | Key Fields |
|---|---|---|
| File Create | File opened or created with write/execute access | `path`, `pid`, `tid`, `access_mask`, `timestamp` |
| File Write | Data written to an existing file | `path`, `pid`, `bytes_written`, `offset`, `timestamp` |
| File Rename | File or directory renamed | `old_path`, `new_path`, `pid`, `timestamp` |
| File Delete | File deletion request | `path`, `pid`, `timestamp` |
| Process Create | New process created | `pid`, `ppid`, `image_path`, `cmdline`, `start_time` |
| Process Terminate | Process exited | `pid`, `exit_code`, `end_time` |
| Registry Key Create | Registry key created | `key_path`, `pid`, `timestamp` |
| Registry Value Write | Registry value set | `key_path`, `value_name`, `value_type`, `value_data`, `pid` |
| Registry Key Delete | Registry key deleted | `key_path`, `pid`, `timestamp` |

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `sysmon.port_name` | `\edrdrv-sysmon` | FilterPort name to connect to |
| `sysmon.recv_buffers` | `2` | Number of concurrent receive buffers |
| `sysmon.buf_min` | `4096` | Minimum receive buffer size |
| `sysmon.buf_max` | `1048576` | Maximum receive buffer size |
| `sysmon.worker_threads` | `2` | Number of I/O worker threads |

---

### libprocmon — Process Monitor Controller

#### Purpose

`libprocmon` manages the lifecycle of `edrpm.dll` instances running inside instrumented processes. It receives behavioral telemetry events generated by hooked API calls, and pushes configuration updates to all active DLL instances. It acts as the controller for the distributed sensor network formed by the injected DLLs.

#### Key Classes and Interfaces

- `ProcMonReceiver`: FilterPort receiver for events from `edrpm.dll` instances (separate port from sysmon)
- `ProcMonConfigPusher`: sends `PROCMON_INJECTION_CONFIG_UPDATE` messages to individual DLL instances or broadcast to all
- `ProcMonEventSource`: `IDataProvider` delivering deserialized `edrpm` events to the pipeline

#### Event Types Received

| Event Type Constant | Description | Key Fields |
|---|---|---|
| `PROCMON_PROCESS_MEMORY_READ` | Cross-process `ReadProcessMemory` call | `src_pid`, `dst_pid`, `address`, `size` |
| `PROCMON_PROCESS_MEMORY_WRITE` | Cross-process `WriteProcessMemory` call | `src_pid`, `dst_pid`, `address`, `size` |
| `PROCMON_API_SET_WINDOWS_HOOK` | `SetWindowsHookEx` called | `pid`, `hook_type`, `is_global`, `module_path` |
| `PROCMON_API_GET_KEYBOARD_STATE` | `GetKeyboardState` polled | `pid`, `call_count`, `window_ms` |
| `PROCMON_API_GET_CLIPBOARD_DATA` | `GetClipboardData` called | `pid`, `format`, `data_size` |
| `PROCMON_COPY_WINDOW_BITMAP` | Screen captured via GDI | `pid`, `hwnd`, `bitmap_size` |
| `PROCMON_DESKTOP_WALLPAPER_SET` | Desktop wallpaper changed | `pid`, `new_path` |
| `PROCMON_THREAD_IMPERSONATION` | Thread token impersonated | `pid`, `tid`, `api_name`, `target_token_user` |
| `PROCMON_INJECTION_CONFIG_UPDATE` | Config push acknowledgment from DLL | `pid`, `config_version` |
| `PROCMON_RAW_DISK_ACCESS` | Raw volume/disk handle opened | `pid`, `path`, `access_mask` |
| `PROCMON_API_ENUM_AUDIO_ENDPOINTS` | Audio endpoint enumeration | `pid`, `data_flow`, `state_mask` |
| `PROCMON_API_WAVE_IN_OPEN` | Audio recording session opened | `pid`, `device_id`, `channels`, `samples_per_sec` |
| `PROCMON_API_BLOCK_INPUT` | `BlockInput` called | `pid`, `block_state` |
| `PROCMON_API_KEYBD_EVENT` | Synthetic keystroke injected | `pid`, `vk`, `flags`, `call_count` |
| `PROCMON_API_SEND_INPUT` | `SendInput` called | `pid`, `input_count`, `input_types` |

#### Configuration Push

`ProcMonConfigPusher` maintains a map of `pid → FilterPort client handle` for every currently instrumented process. When the policy engine updates hook configuration (e.g., enabling audio capture monitoring for a specific process category), it submits a `PROCMON_INJECTION_CONFIG_UPDATE` command to `ProcMonConfigPusher`, which serializes the new configuration as LBVS and sends it to the target DLL instances. Broadcast configuration updates (affecting all processes) are sent sequentially through the per-process handle map. If a process has terminated since the last update, the send fails gracefully and the handle is removed from the map.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `procmon.port_name` | `\edrdrv-procmon` | FilterPort name for DLL event receive |
| `procmon.worker_threads` | `2` | Receiver worker thread count |
| `procmon.config_push_timeout_ms` | `1000` | Timeout for per-process config push |

---

### libnetmon — Network Monitor

<picture>
  <source srcset="assets/Network_traffic_analysis_visuali…_202605010256.avif" type="image/avif">
  <img src="assets/Network_traffic_analysis_visuali…_202605010256.avif" alt="Network traffic analysis visualization" width="100%">
</picture>

#### Purpose

`libnetmon` receives network event telemetry from the WFP-based kernel network monitor and presents it as a structured event stream to the pipeline. It enriches raw connection tuples with process context, performs protocol detection for application-layer classification, and maintains an active connection table for flow tracking.

#### Key Classes and Interfaces

- `NetMonReceiver`: FilterPort receiver for network events from `edrdrv.sys` network monitor subsystem
- `ConnectionTracker`: maintains an in-memory table of active TCP connections, indexed by 5-tuple
- `ProtocolDetector`: classifies network flows as HTTP, FTP, DNS, or unknown based on port heuristics and payload inspection
- `NetMonEventSource`: `IDataProvider` publishing enriched network events to the pipeline

#### Event Types and Schema

| Event Type | Trigger | Schema Fields |
|---|---|---|
| `NETMON_CONNECT_OUT` | Outbound TCP connection established | `pid`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `protocol`, `timestamp` |
| `NETMON_CONNECT_IN` | Inbound TCP connection accepted | `pid`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `protocol`, `timestamp` |
| `NETMON_LISTEN` | TCP socket enters listening state | `pid`, `local_addr`, `local_port`, `backlog`, `timestamp` |
| `NETMON_REQUEST_DNS` | DNS query captured (UDP/TCP port 53) | `pid`, `query_name`, `query_type`, `server_addr`, `timestamp` |
| `NETMON_REQUEST_DATA_HTTP` | HTTP request detected | `pid`, `method`, `host`, `uri`, `user_agent`, `content_type`, `timestamp` |
| `NETMON_REQUEST_DATA_FTP` | FTP command detected | `pid`, `command`, `argument`, `server_addr`, `timestamp` |
| `NETMON_CONNECTION_CLOSED` | TCP connection closed | `pid`, `5_tuple`, `bytes_sent`, `bytes_recv`, `duration_ms` |

#### Connection Tracking

The `ConnectionTracker` maintains a hash map keyed on the 4-tuple (local IP, local port, remote IP, remote port). On `NETMON_CONNECT_OUT` or `NETMON_CONNECT_IN`, an entry is created recording the originating PID, start timestamp, and flow bytes counters. On `NETMON_CONNECTION_CLOSED`, the entry is finalized and a connection summary event is emitted that includes total bytes transferred and duration. Entries for connections that close without a corresponding close event (e.g., due to NAT timeout or driver restart) are expired after a configurable idle timeout (default 300 seconds).

#### Status Codes and Protocol Detection

`ProtocolDetector` uses a layered heuristic: first, well-known port assignments (80/443 → HTTP, 21 → FTP, 53 → DNS, 25/465/587 → SMTP, 3389 → RDP). Second, for connections on non-standard ports, it inspects the first few bytes of the first data payload (captured at the `FWPM_LAYER_STREAM` layer when deep inspection is enabled) for protocol magic bytes. Detected protocol is recorded in the `protocol` field of all events associated with the flow.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `netmon.port_name` | `\edrdrv-netmon` | FilterPort name for network events |
| `netmon.worker_threads` | `2` | Receiver worker thread count |
| `netmon.connection_idle_timeout_s` | `300` | Idle connection expiry |
| `netmon.deep_inspection` | `false` | Enable stream-layer payload inspection |
| `netmon.dns_capture` | `true` | Enable DNS query capture |

---

### libsyswin — Windows System Abstraction

#### Purpose

`libsyswin` provides a caching abstraction layer over Windows system APIs for process, file, user, and signature information. It serves the enrichment stage of the QSC pipeline, providing the contextual metadata needed to classify events accurately. All data providers implement aggressive caching to avoid repeated system calls for the same entity.

#### Key Classes and Interfaces

- `ProcessDataProvider`: implements `IDataProvider` for process metadata
- `FileDataProvider`: implements `IDataProvider` for file metadata and hashes
- `UserDataProvider`: provides SID-to-username and session information
- `SignatureDataProvider`: provides Authenticode signature and publisher chain information
- `SymlinkResolver`: resolves NT device paths (e.g., `\Device\HarddiskVolume3\...`) to Win32 paths

#### ProcessDataProvider

`ProcessDataProvider` maintains an in-memory cache of process records indexed by PID. Each record contains: image path, command line, parent PID, username, session ID, token integrity level, creation time, and the process hierarchy chain (list of ancestor PIDs resolved recursively up to the session root). Records have a time-to-live of 10 minutes from last access, after which they are evicted and re-queried from the OS. The enrichment operation `enrichProcessInfo(pid, Variant& event)` adds all available process metadata fields to the event dictionary in a single call. Process termination events from `libsysmon` are used to proactively evict cache entries, maintaining accuracy for PID reuse scenarios.

The process hierarchy is particularly important for behavioral detections: many attack patterns are identified by the parent-child relationship chain (e.g., `Word.exe` spawning `cmd.exe` spawning `PowerShell.exe`). The hierarchy is stored as a `Sequence` of PID values, traversed from child to root, with each level's image name and command line embedded.

#### FileDataProvider

`FileDataProvider` maintains a cache of file records indexed by normalized NT path. Each record contains: Win32 path, file size, last write time, SHA-256 hash (computed on demand and cached), PE header metadata (if the file is a PE image: subsystem, timestamp, imports, exports, machine type), and MIME type heuristic. Hash computation is performed asynchronously on the `SlowLocalFS` lane to avoid blocking Fast lane event processing. NT native APIs (`NtOpenDirectoryObject`, `NtQueryDirectoryObject`) are used for device path enumeration and symbolic link resolution, enabling path normalization for files accessed via device paths, junction points, and hard links. The `SymlinkResolver` component maintains a cache of `\Device\HarddiskVolumeN` → drive letter mappings, refreshed when volume mount changes are detected.

#### UserDataProvider

`UserDataProvider` resolves security identifiers (SIDs) to human-readable account names using `LookupAccountSid` with result caching keyed on the SID binary representation. It also provides session information (session ID, session type — console/RDP/service) by wrapping `WTSQuerySessionInformation`. This data is used by the enrichment stage to add `username`, `domain`, and `session_type` fields to every event, which are critical for user-behavior-based detections.

#### SignatureDataProvider

`SignatureDataProvider` performs Authenticode signature verification using the `WinVerifyTrust` API with the `WINTRUST_ACTION_GENERIC_VERIFY_V2` action. For each file queried, it returns: signature status (valid/invalid/unsigned), the subject CN of the leaf certificate, the issuer CN, the certificate SHA-1 thumbprint, and whether the signature chains to a trusted root in the system certificate store. Results are cached keyed on file path + last write time to invalidate the cache when a file is replaced. This data is used by the enrichment stage to add `signed`, `signer`, and `signer_trusted` fields to file-related events.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `syswin.process_cache_ttl_s` | `600` | Process cache entry TTL in seconds |
| `syswin.file_hash_algo` | `sha256` | Hash algorithm for file hashing |
| `syswin.file_hash_max_size_mb` | `256` | Skip hashing files larger than this |
| `syswin.signature_cache_size` | `10000` | Maximum signature cache entries |
| `syswin.user_cache_ttl_s` | `300` | User info cache TTL |

---

### libedr — EDR Core Logic

<picture>
  <source srcset="assets/Policy_engine_visualizing_event_…_202605010255.avif" type="image/avif">
  <img src="assets/Policy_engine_visualizing_event_…_202605010255.avif" alt="Policy engine event flow" width="100%">
</picture>

#### Purpose

`libedr` is the detection brain of OpenArmor. It defines the complete Low-Level Event (LLE) taxonomy, implements the lane system for performance management, hosts the policy compiler, and drives the QSC pipeline. All behavioral detection logic is expressed through compiled policy rules evaluated by `libedr` against the enriched event stream.

#### Key Classes and Interfaces

- `LleProcessor`: central event processor, dispatches LLE events to the QSC pipeline
- `LaneManager`: manages Fast/SlowLocalFS/SlowNetwork lane assignment and exception handling
- `IPolicyCompiler`: interface for the policy compilation subsystem
- `PolicyGroup`: compiled representation of a policy rule set
- `PatternMatcher`: evaluates event fields against compiled patterns
- `MleGenerator`: produces Mid-Level Events (MLEs) from policy match results

#### LLE Event Taxonomy

The following table enumerates all Low-Level Event types in the OpenArmor taxonomy:

| LLE Constant | Source Subsystem | Description |
|---|---|---|
| `LLE_PROCESS_CREATE` | libsysmon (procmon) | New process created |
| `LLE_PROCESS_TERMINATE` | libsysmon (procmon) | Process terminated |
| `LLE_FILE_CREATE` | libsysmon (filemon) | File created or opened |
| `LLE_FILE_WRITE` | libsysmon (filemon) | Data written to file |
| `LLE_FILE_RENAME` | libsysmon (filemon) | File renamed |
| `LLE_FILE_DELETE` | libsysmon (filemon) | File deleted |
| `LLE_REGISTRY_KEY_CREATE` | libsysmon (regmon) | Registry key created |
| `LLE_REGISTRY_VALUE_WRITE` | libsysmon (regmon) | Registry value written |
| `LLE_REGISTRY_KEY_DELETE` | libsysmon (regmon) | Registry key deleted |
| `LLE_NETWORK_CONNECT_OUT` | libnetmon | Outbound network connection |
| `LLE_NETWORK_CONNECT_IN` | libnetmon | Inbound network connection |
| `LLE_NETWORK_LISTEN` | libnetmon | Network socket entering listen state |
| `LLE_NETWORK_DNS_REQUEST` | libnetmon | DNS query issued |
| `LLE_NETWORK_HTTP_REQUEST` | libnetmon | HTTP request detected |
| `LLE_NETWORK_FTP_REQUEST` | libnetmon | FTP command detected |
| `LLE_API_CLIPBOARD_ACCESS` | libprocmon | Clipboard data accessed |
| `LLE_API_KEYBOARD_CAPTURE` | libprocmon | Keyboard state polled |
| `LLE_API_SCREEN_CAPTURE` | libprocmon | Window bitmap copied |
| `LLE_API_AUDIO_CAPTURE` | libprocmon | Audio recording opened |
| `LLE_API_WINDOW_HOOK` | libprocmon | Global window hook installed |
| `LLE_API_INPUT_INJECTION` | libprocmon | Synthetic input injected |
| `LLE_PROCESS_MEMORY_READ` | libprocmon | Cross-process memory read |
| `LLE_PROCESS_MEMORY_WRITE` | libprocmon | Cross-process memory write |
| `LLE_THREAD_IMPERSONATION` | libprocmon | Thread token impersonated |
| `LLE_RAW_DISK_ACCESS` | libprocmon | Raw disk or volume access |
| `LLE_WALLPAPER_CHANGE` | libprocmon | Desktop wallpaper changed |

#### Mid-Level Events (MLEs)

MLEs are synthesized by the policy engine when a pattern match or behavioral correlation fires. They represent a higher-level security-relevant conclusion drawn from one or more LLEs. MLEs carry: a `threat_category` (e.g., `ransomware`, `credential_dumping`, `lateral_movement`, `data_exfiltration`), a `confidence_score` (0–100), a list of contributing LLE event IDs, the PID and image path of the implicated process, and the policy rule identifier that triggered the match. MLEs are the primary output of the pipeline's pattern matching stage and are routed to the `apply_policy` stage for response action determination.

#### Lane System

The lane system is the performance management core of `libedr`. Every event processing call is annotated with its current lane assignment via a thread-local variable. Three lane levels are defined:

**Fast Lane**: Used for process creation and termination events, and registry events from the `regmon` subsystem. Processing must complete within microseconds. No file I/O, no network calls, and no calls to `libsyswin`'s file hash computation are permitted. If a Fast lane event requires file hashing (e.g., because the process image is new and not yet in the hash cache), the event is re-queued to the `SlowLocalFS` lane and the Fast lane thread immediately proceeds to the next event.

**SlowLocalFS Lane**: Used for file system events that require hash computation, PE header parsing, or other local disk I/O. Processing may take milliseconds. Network calls are still prohibited. Events that require FLS (cloud file reputation) lookup are re-queued to the `SlowNetwork` lane.

**SlowNetwork Lane**: Used for events requiring any form of network I/O, including FLS reputation lookups, Valkyrie verdict submissions, and DNS resolution for network connection events. Processing may take hundreds of milliseconds due to network latency.

The `checkCurLane(LaneType required)` function is called at the entry point of every operation with a minimum lane requirement. If the current thread is on a lane lower than required, it throws `SlowLaneOperationException(required)`. The lane manager catches this exception, saves the partially-processed event, re-queues it to the appropriate lane, and returns immediately. This mechanism ensures strict lane discipline without requiring every function to carry lane context as an explicit parameter.

#### Policy Compiler

The `IPolicyCompiler` interface accepts a `Variant` policy definition (loaded from JSON by `edrdata`) and produces a compiled `PolicyGroup` object optimized for fast evaluation. The compilation process:

1. Parses pattern expressions (field-path, operator, value) into a bytecode representation for the pattern evaluator
2. Groups patterns by LLE type to enable O(1) dispatch: only patterns relevant to the current event type are evaluated
3. Compiles `EventsMatching` temporal correlation rules (e.g., "process A creates file B and then connects to IP C within 30 seconds") into a finite-state automaton
4. Validates all policy rule references for consistency, producing structured `CompileError` records for any invalid rules

`PolicyGroup` contains two sub-groups: `PatternsMatching` (single-event stateless rules) and `EventsMatching` (multi-event temporal correlation rules). `PolicySourceLocation` records the source file, line, and column for each compiled rule, enabling precise error reporting and rule attribution in alert metadata. Policy recompilation is triggered by the `PolicyIsUpdated` message and is performed on a background thread; the compiled policy is atomically swapped into the active slot without interrupting in-flight event processing.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `edr.fast_lane_threads` | `2` | Thread count for Fast lane processing |
| `edr.slow_local_threads` | `4` | Thread count for SlowLocalFS lane |
| `edr.slow_network_threads` | `2` | Thread count for SlowNetwork lane |
| `edr.mle_output_enabled` | `true` | Emit MLEs to cloud telemetry |
| `edr.policy_hot_reload` | `true` | Allow policy reload without service restart |
| `edr.correlation_window_s` | `30` | Default temporal correlation window |

---

### libcloud — Cloud Integration

<picture>
  <source srcset="assets/Cloud_communication_architecture…_202605010255.avif" type="image/avif">
  <img src="assets/Cloud_communication_architecture…_202605010255.avif" alt="Cloud communication architecture" width="100%">
</picture>

#### Purpose

`libcloud` provides all cloud connectivity for the OpenArmor agent: endpoint enrollment, heartbeat, configuration and policy retrieval, telemetry upload via AWS Firehose, file reputation lookup via the File List Service (FLS), and secondary sandbox verdict via Valkyrie. It implements offline buffering and retry logic to handle intermittent connectivity.

#### Key Classes and Interfaces

- `CloudService`: central `IService` managing all cloud operations; subscribes to `PolicyIsUpdated` and `CloudConfigurationIsChanged`
- `HeartbeatTimer`: periodic task (default 30 seconds) sending endpoint health status to the management console
- `FirehoseClient`: wraps the AWS SDK C++ Firehose client; handles batching and retry
- `HttpClient`: REST client for management API endpoints; uses OpenSSL for TLS
- `FlsClient`: File List Service client; supports protocol v4 and v7
- `GcpClient`: Google Cloud Platform telemetry client
- `OfflineBuffer`: disk-backed queue for events accumulated during cloud connectivity loss
- `EnrollmentManager`: handles initial device enrollment and credential storage

#### CloudService Operations

| Operation | Trigger | Interval/Condition |
|---|---|---|
| `heartbeat()` | Timer | Every 30 seconds |
| `getConfig()` | Startup, `CloudConfigurationIsChanged` | On demand |
| `getPolicy()` | Startup, `PolicyIsUpdated` | On demand |
| `reportEndpointInfo()` | Startup, after enrollment | Once per startup |
| `enroll()` | First run or re-enrollment | Manual trigger |
| `publishEvents(batch)` | Pipeline output stage | Continuously, batched |
| `getFlsVerdict(hash)` | Pipeline stage 5 | Per unique file hash |
| `getValkyrieVerdict(hash)` | Pipeline stage 6 | Per suspicious file |

#### AWS Firehose Integration

The `FirehoseClient` uses the AWS SDK for C++ (`awssdkcpp`) to deliver telemetry events to a configured Kinesis Data Firehose stream. Events are batched by the pipeline output stage into payloads of up to 500 records or 4 MB (Firehose batch limits) and submitted via `PutRecordBatch`. The client is configured with AWS access key, secret key, stream name, and region from the agent configuration. On failure (network error or Firehose throttle), the client applies exponential backoff with jitter and re-queues the batch via the `OfflineBuffer`. The `SerialCommandProcessor` ensures that Firehose submissions maintain event ordering guarantees; events are never submitted out of order to the stream.

#### FLS Protocol (File List Service)

The File List Service provides file hash reputation verdicts used at pipeline stage 5. OpenArmor supports two FLS protocol versions:

**FLS v4**: A simple HTTP POST protocol. The client submits a JSON body containing an array of SHA-256 hashes. The server returns a JSON array of verdict objects, each containing: hash, verdict (`clean`/`malicious`/`unknown`), confidence score, and threat category string.

**FLS v7**: An enhanced protocol supporting batch queries over a persistent HTTP/2 connection, with gRPC transport and Protobuf encoding. v7 provides lower latency and higher throughput for large hash batches. The client negotiates the protocol version during the initial connection handshake. v7 verdicts include additional metadata: malware family classification, first-seen and last-seen timestamps, and geographic prevalence data.

Verdicts are cached locally (keyed on hash, TTL configurable, default 24 hours) to avoid repeated lookups for the same file. Unknown hashes are submitted to Valkyrie for dynamic analysis if configured.

#### Offline Buffering

The `OfflineBuffer` is a disk-backed queue stored in the agent's data directory. When cloud connectivity is unavailable, pipeline output events are serialized to this buffer. When connectivity is restored, the buffer is replayed to the cloud in FIFO order. The buffer is bounded by a configurable maximum disk size (default 256 MB); when full, the oldest events are discarded to make room for new ones, ensuring that the most recent telemetry is always preserved.

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `cloud.management_url` | (set at enrollment) | Management console REST endpoint |
| `cloud.heartbeat_interval_s` | `30` | Heartbeat interval in seconds |
| `cloud.firehose.access_key` | (required) | AWS access key ID |
| `cloud.firehose.secret_key` | (required) | AWS secret access key |
| `cloud.firehose.stream` | (required) | Kinesis Firehose stream name |
| `cloud.firehose.region` | `us-east-1` | AWS region |
| `cloud.firehose.batch_size` | `500` | Maximum records per batch |
| `cloud.fls.url` | (set at enrollment) | FLS endpoint URL |
| `cloud.fls.protocol_version` | `7` | FLS protocol version (4 or 7) |
| `cloud.fls.verdict_cache_ttl_s` | `86400` | Verdict cache TTL in seconds |
| `cloud.valkyrie.enabled` | `true` | Enable Valkyrie submissions |
| `cloud.offline_buffer_max_mb` | `256` | Maximum offline buffer size |
| `cloud.tls_verify` | `true` | Verify TLS certificates |
| `cloud.gcp.enabled` | `false` | Enable GCP telemetry pipeline |
| `cloud.retry_max_attempts` | `5` | Maximum retry attempts |
| `cloud.retry_base_delay_ms` | `1000` | Base delay for exponential backoff |

---

### libcore — Core Framework

#### Purpose

`libcore` is the foundational framework library upon which the entire OpenArmor platform is constructed. It provides: the object model (`IObject`, `ObjPtr<T>`, `ObjectManager`), the service lifecycle framework (`IService`, Catalog), the universal data container (`Variant`), binary serialization (LBVS), the command bus (`ICommand`, `ICommandProcessor`, `ThreadPool`), the message pub-sub bus, cryptographic utilities (xxHash, AES-128), structured error handling, and logging integration.

#### Object Factory

The `ObjectManager` implements the factory pattern using a static registry of `ClassId → FactoryFn` mappings. Factory functions are registered via the `REGISTER_IMPLEMENTATION` macro placed in each component's `.cpp` file, executed during C++ static initialization. `ClassId` values are computed at compile time via a constexpr FNV-1a hash of the class name string, ensuring zero-collision mapping without a central registry file. The factory function receives a `Variant` configuration block and returns an `ObjPtr<IObject>`. Runtime object creation is performed by `ObjectManager::createObject(ClassId)` or `ObjectManager::createObjectWithConfig(ClassId, Variant config)`.

#### Command Bus and ThreadPool

The `ThreadPool` implements `ICommandProcessor` with a fixed pool of worker threads. The pool uses a lock-free MPMC queue (based on a ring buffer with atomic head/tail indices) for command submission, eliminating mutex contention on the submission path in common cases. Worker threads block on a POSIX semaphore (via `WaitForSingleObject` on Windows) and are signaled once per enqueued command. The `SerialCommandProcessor` wraps a `ThreadPool` and adds a sequence number to each command, reordering completions to maintain strict FIFO delivery to the downstream result handler. The `RetryCommandProcessor` wraps any `ICommandProcessor` and re-submits commands that complete with a retryable error code after an exponential backoff delay.

#### Message Pub-Sub Bus

The message bus (`IMessageBus`, implemented as a singleton accessed via `getMessageBus()`) maintains a `std::unordered_map<MessageId, std::vector<ObjPtr<IDataReceiver>>>` of subscriber lists. `subscribeToMessage(MessageId, receiver)` appends to the subscriber list under a shared lock. `publishMessage(MessageId, data)` acquires a shared read lock, copies the subscriber list, releases the lock, then calls `receiver->put(data)` for each subscriber outside the lock to avoid re-entrancy issues. Message delivery is synchronous on the publishing thread; publishers must not hold any component-level locks when calling `publishMessage`.

#### LBVS Binary Serialization

LBVS (Length-Based Value Serialization) is a compact binary format for `Variant` values designed for zero-copy deserialization. The wire format:

```
[1 byte type tag] [4 bytes little-endian length] [N bytes value data]
```

For `Dictionary` types, the value data is a sequence of key-value pairs encoded as:
```
[LBVS-encoded string key] [LBVS-encoded Variant value]
```

For `Sequence` types, the value data is a contiguous sequence of LBVS-encoded `Variant` values. Integer and Boolean values encode their data directly in the value bytes (8 bytes for Integer, 1 byte for Boolean). The `LbvsSerializer::serialize(Variant)` function produces a `std::vector<uint8_t>`. The `LbvsDeserializer::deserialize(const uint8_t*, size_t)` function walks the buffer in a single linear pass with no heap allocation for scalar types, producing a `Variant` tree that references string and binary data in-place from the source buffer when possible (zero-copy for read-only consumers).

#### Error Hierarchy

All functions in `libcore` and dependent libraries report errors via a structured `ErrorCode` enum rather than exceptions (exceptions are reserved for cross-lane signaling in `libedr`). The error hierarchy is organized into ranges:

| Range | Category | Examples |
|---|---|---|
| 0x0000–0x00FF | Success | `ErrorCode::OK` |
| 0x0100–0x01FF | Object model errors | `ClassNotFound`, `InterfaceNotSupported` |
| 0x0200–0x02FF | Serialization errors | `InvalidTypeTag`, `TruncatedBuffer` |
| 0x0300–0x03FF | I/O errors | `PortConnectFailed`, `SendTimeout` |
| 0x0400–0x04FF | Policy errors | `CompileError`, `InvalidPattern` |
| 0x0500–0x05FF | Cloud errors | `EnrollmentFailed`, `CredentialExpired` |
| 0x8000–0xFFFF | Platform/Win32 errors | HRESULT-mapped codes |

#### Cryptographic Utilities

The `crypt` module in `libcore` provides two cryptographic primitives used across the platform:

**xxHash**: The 64-bit xxHash algorithm is used for non-cryptographic hashing needs: hash table keying for cache lookup, event deduplication fingerprinting, and ClassId computation. xxHash is extremely fast (multi-GB/s throughput) and produces well-distributed 64-bit hash values suitable for these use cases.

**AES-128-CBC**: Used for encrypting locally stored credentials (FLS API keys, enrollment tokens) at rest, using a machine-specific key derived from the machine SID. OpenSSL (`EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`) provides the implementation.

#### Logging Integration

`libcore` integrates with `log4cplus` for structured, leveled logging. A global `Logger` object is accessible via `getLogger(component_name)`, returning a named logger that prepends the component name to all messages. Log levels: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`. Log output is configurable via a `log4cplus.properties` file: available appenders include `RollingFileAppender` (default: `edrsvc.log`, 10 MB per file, 5 files retained), `ConsoleAppender` (for `edrcon run` foreground mode), and `NTEventLogAppender` (for Windows Event Log integration). Log messages include a high-resolution timestamp, thread ID, component name, and log level prefix. Sensitive data (file hashes, IP addresses, process command lines) is automatically masked in log output when `log.mask_sensitive = true`.

---

### edrcon — Control Utility

#### Purpose

`edrcon` is the command-line administrative interface for the OpenArmor agent. It communicates with `edrsvc.exe` via the local RPC named pipe to issue control commands, query agent state, compile policies, and perform diagnostic operations. It is intended for use by security administrators and by automation tooling.

#### Key Classes and Interfaces

- `RpcClient`: connects to the `edrsvc` RPC named pipe and sends `ICommand`-encoded requests
- `OutputFormatter`: formats command results as human-readable text or structured JSON
- `PolicyCompilerClient`: sends policy source to `edrsvc` for compilation and retrieves errors
- `FileAnalyzer`: requests on-demand file analysis (hash + FLS + signature) from `edrsvc`

#### Usage Reference

All `edrcon` commands follow the pattern: `edrcon <command> [options]`. Options can be passed as `--key value` or `--key=value`. The `--format json` flag is available on all commands that produce structured output.

```
# Start the OpenArmor service via the Windows Service Control Manager
edrcon start

# Stop the OpenArmor service
edrcon stop

# Run the agent in foreground mode (no SCM; for debugging)
edrcon run [--config C:\openarmor\config.json]

# Run in verbose debug mode (maximum log level, console output)
edrcon debug [--verbose] [--component libcloud]

# Dump current agent state to stdout or file
edrcon dump [--format json] [--output C:\openarmor\state_dump.json]

# Compile a policy file and report any errors
edrcon compile --policy C:\openarmor\policies\corporate.json

# Request on-demand analysis of a specific file
edrcon file --hash C:\path\to\suspicious.exe
edrcon file --hash C:\path\to\suspicious.exe --format json

# Query information about a running process
edrcon process --pid 1234
edrcon process --pid 1234 --format json

# Start an RPC server for remote administration (bind to a specific port)
edrcon rpcserver --port 8080

# Temporarily disable self-protection (requires Administrator elevation)
# Useful for uninstallation or driver update
edrcon unprot [--timeout 60]

# Wait for the agent to reach a target operational state
edrcon wait --state running --timeout 30
edrcon wait --state stopped --timeout 60

# Enroll this endpoint with the cloud management console
edrcon enroll --url https://console.openarmor.example.com --key <enrollment-key>

# Trigger an immediate policy refresh from the cloud
edrcon policy refresh

# Display current agent version and build information
edrcon version
```

#### Output Formats

By default, `edrcon` produces human-readable tabular output suitable for interactive terminal use. With `--format json`, all output is produced as a single JSON object written to stdout, enabling integration with shell scripts and SIEM tooling. Exit codes follow UNIX conventions: 0 for success, 1 for command failure, 2 for usage error, 3 for communication failure (RPC pipe unavailable).

#### Configuration Options

| Parameter | Default | Description |
|---|---|---|
| `edrcon.rpc_pipe` | `\\.\pipe\openarmor-rpc` | Named pipe path for RPC |
| `edrcon.connect_timeout_s` | `10` | RPC connection timeout |
| `edrcon.command_timeout_s` | `30` | Individual command timeout |

---

### edrmm — Memory Manager

#### Purpose

`edrmm` is a diagnostic and quality-assurance component that provides memory leak detection capabilities for debug and test builds of the OpenArmor agent. It is not active in production release builds. It wraps the global C++ allocation functions and tracks every allocation and deallocation, enabling detection of long-lived allocations that may indicate object lifecycle issues or resource leaks.

#### Key Classes and Interfaces

- `MemoryLeakMonitor`: singleton that hooks `malloc`/`free`/`new`/`delete` in debug builds to record allocation call stacks and sizes
- `LeakReporter`: serializes the allocation table to a structured JSON report file

#### API Reference

```cpp
// Begin recording all allocations from this point forward
edrmm::startMemoryLeaksMonitoring();

// Finalize monitoring and write a report of all live allocations
// to the specified path (or a timestamped default path)
edrmm::saveMemoryLeaks(const std::string& output_path = "");
```

#### Usage in Testing

In the automated test suite (using `catch2`), `startMemoryLeaksMonitoring()` is called at the beginning of each test case's setup fixture, and `saveMemoryLeaks()` is called in the teardown fixture. The test framework inspects the report for any leaked allocations that were created during the test case. Any leak fails the test. This approach catches reference counting bugs in `ObjPtr<T>` usage, missing `release()` calls on raw `IObject` pointers, and event records that are allocated but never consumed by the pipeline.

#### Operational Characteristics

`edrmm` is a compile-time optional component controlled by the `EDRMM_ENABLED` preprocessor flag. When disabled (the default for release builds), all `edrmm` API calls are compiled to no-ops with zero runtime overhead. When enabled, allocation tracking introduces approximately 3–5% overhead on allocation-heavy workloads, which is acceptable for test and debug environments. The allocation table is protected by a spinlock to support multi-threaded tracking. Call stack capture uses `RtlCaptureStackBackTrace` on Windows, limited to 32 frames to balance accuracy against storage overhead.

---

### edrext — Extensions / System Info

#### Purpose

`edrext` provides structured access to comprehensive endpoint metadata used during enrollment, heartbeat, and cloud reporting. It queries OS version information, network adapter configuration, host identity, domain membership, user sessions, and other environmental data, presenting all results as `Variant` dictionaries for direct inclusion in cloud API payloads.

#### Key Classes and Interfaces

- `OsInfoProvider`: collects OS version, edition, and uptime information
- `NetworkAdapterProvider`: enumerates network adapters with full address information
- `HostInfoProvider`: collects hostname, domain, machine SID, and hardware identifiers
- `SessionInfoProvider`: enumerates active user sessions and their properties

#### OS Information

The `OsInfoProvider` queries the following data:

| Field | Source | Example Value |
|---|---|---|
| `os.family` | `RtlGetVersion` | `Windows` |
| `os.version` | `RtlGetVersion` | `10.0.19045` |
| `os.build` | `RtlGetVersion` | `19045` |
| `os.friendly_name` | Registry: `ProductName` | `Windows 10 Pro` |
| `os.edition` | Registry: `EditionID` | `Professional` |
| `os.uptime_s` | `GetTickCount64` | `86400` |
| `os.boot_time` | `GetTickCount64` + current time | ISO 8601 timestamp |
| `os.architecture` | `GetNativeSystemInfo` | `x64` |
| `os.install_date` | Registry: `InstallDate` | ISO 8601 timestamp |

#### Network Adapter Enumeration

The `NetworkAdapterProvider` uses `GetAdaptersAddresses` with the `GAA_FLAG_INCLUDE_ALL_INTERFACES` flag to enumerate all network adapters. For each adapter, it records:

| Field | Description |
|---|---|
| `adapter.name` | Adapter friendly name |
| `adapter.description` | Adapter hardware description |
| `adapter.mac` | MAC address (colon-separated hex) |
| `adapter.ipv4` | List of IPv4 unicast addresses with prefix lengths |
| `adapter.ipv6` | List of IPv6 unicast addresses with prefix lengths |
| `adapter.dns_servers` | List of DNS server addresses (IPv4 and IPv6) |
| `adapter.gateway` | Default gateway addresses |
| `adapter.type` | Adapter type code (Ethernet, WiFi, Loopback, etc.) |
| `adapter.status` | Operational status (Up, Down, etc.) |
| `adapter.dhcp_enabled` | Whether the adapter uses DHCP |

#### Host and Domain Information

| Field | Source | Description |
|---|---|---|
| `host.name` | `GetComputerNameEx(ComputerNameDnsHostname)` | Fully qualified hostname |
| `host.domain` | `NetGetJoinInformation` | Domain or workgroup name |
| `host.domain_joined` | `NetGetJoinInformation` | Boolean domain membership flag |
| `host.machine_sid` | SAM database query | Machine security identifier |
| `host.hardware_uuid` | WMI `Win32_ComputerSystemProduct.UUID` | Hardware UUID for device identity |

#### Session Management

`SessionInfoProvider` uses the WTS (Windows Terminal Services) API to enumerate all active and disconnected sessions on the endpoint. For each session:

| Field | Description |
|---|---|
| `session.id` | Session ID |
| `session.username` | Logged-on username |
| `session.domain` | User domain |
| `session.state` | `Active`, `Disconnected`, `Idle`, etc. |
| `session.type` | `Console`, `RDP-Tcp`, `Service` |
| `session.logon_time` | Session logon timestamp |

This session data is included in the enrollment payload and in heartbeat messages, enabling the management console to track which users are active on each endpoint.

---

### edrdata — Data & Scenarios

#### Purpose

`edrdata` is not a library with executable logic but rather the data repository containing all QSC (Query Scenario Configuration) pipeline definitions, policy schema definitions, and scenario script files. It defines the pipeline topology, the event filter rules, enrichment specifications, pattern libraries, and output routing configuration. The QSC pipeline is the processing backbone that every Low-Level Event passes through from raw telemetry to detection decision.

#### QSC Pipeline Overview

The QSC pipeline consists of seven sequential stages. Each stage receives a `Variant` event dictionary from the previous stage, performs its operation, and passes a (potentially modified) event dictionary to the next stage. Stages may also short-circuit the pipeline (drop the event) or fork it (produce multiple output events). The pipeline definition for each event type is stored as a JSON scenario file in `edrdata/scenarios/`.

#### Complete Pipeline Stage Reference

| Stage | Name | Input | Output | Description |
|---|---|---|---|---|
| 1 | `filter_lle` | Raw LLE `Variant` from receiver | Filtered LLE or DROP | Applies static exclusion rules; drops events matching known-clean process/path/user patterns to reduce pipeline load |
| 2 | `enrich_lle` | Filtered LLE | Enriched LLE with metadata | Calls `libsyswin` providers to add process hierarchy, file hash, signer info, username, session type |
| 3 | `match_patterns` | Enriched LLE | LLE + matched pattern list or DROP | Evaluates compiled `PolicyGroup.PatternsMatching` rules; attaches list of matched rule IDs |
| 4 | `apply_policy` | LLE + pattern matches | LLE + policy action | Applies `PolicyGroup.EventsMatching` temporal correlation; determines response action (allow/alert/block/kill) |
| 5 | `get_fls_verdict` | LLE + policy action | LLE + FLS verdict | For file-related events with a hash, queries FLS for reputation; updates action if malicious verdict received |
| 6 | `check_for_valkyrie` | LLE + FLS verdict | LLE + Valkyrie verdict | For unknown files that matched suspicious patterns, submits to Valkyrie; awaits or polls for dynamic verdict |
| 7 | `output` | LLE + all verdicts and actions | Side effects only | Routes event to: alert stream, block action execution, cloud telemetry upload, local event log |

#### Stage 1: filter_lle — Static Exclusion Filter

**Input fields consumed**: `lle_type`, `process.image_path`, `file.path`, `network.remote_addr`, `user.name`

**Output**: Event dictionary passed through unchanged, or DROP signal

**Exclusion rule format** (JSON):
```json
{
  "filter_lle": {
    "exclusions": [
      {
        "lle_types": ["LLE_FILE_CREATE", "LLE_FILE_WRITE"],
        "conditions": [
          { "field": "file.path", "op": "prefix", "value": "C:\\Windows\\SoftwareDistribution\\" },
          { "field": "process.image_path", "op": "suffix", "value": "\\TiWorker.exe" }
        ],
        "match": "all"
      }
    ]
  }
}
```

#### Stage 2: enrich_lle — Contextual Enrichment

**Input fields consumed**: `pid`, `file.path` (for file events), `network.remote_addr` (for network events)

**Fields added to output**:

| Field Added | Source Provider | Description |
|---|---|---|
| `process.image_path` | `ProcessDataProvider` | Full image path of originating process |
| `process.cmdline` | `ProcessDataProvider` | Command line of originating process |
| `process.hierarchy` | `ProcessDataProvider` | List of ancestor image names |
| `process.username` | `UserDataProvider` | Username of process token |
| `process.session_type` | `UserDataProvider` | Console/RDP/Service |
| `process.integrity` | `ProcessDataProvider` | Token integrity level |
| `file.hash_sha256` | `FileDataProvider` | SHA-256 of file (async, SlowLocalFS) |
| `file.size` | `FileDataProvider` | File size in bytes |
| `file.signed` | `SignatureDataProvider` | Whether file has valid signature |
| `file.signer` | `SignatureDataProvider` | Signing certificate CN |
| `file.signer_trusted` | `SignatureDataProvider` | Whether signer chains to trusted root |
| `file.pe_subsystem` | `FileDataProvider` | PE subsystem (GUI/Console/Driver) |

#### Stage 3: match_patterns — Behavioral Pattern Evaluation

**Input fields consumed**: All fields in the enriched LLE dictionary

**Fields added to output**: `matched_patterns` (Sequence of matched rule IDs), `pattern_score` (aggregate threat score)

**Pattern rule format** (JSON):
```json
{
  "id": "rule.office.spawns.shell",
  "name": "Office application spawning command shell",
  "lle_type": "LLE_PROCESS_CREATE",
  "score": 80,
  "conditions": [
    {
      "field": "process.hierarchy[1].image_name",
      "op": "in",
      "value": ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"]
    },
    {
      "field": "process.image_name",
      "op": "in",
      "value": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
    }
  ],
  "match": "all"
}
```

#### Stage 4: apply_policy — Policy Decision and Temporal Correlation

**Input fields consumed**: `matched_patterns`, `pattern_score`, all enriched LLE fields

**Fields added to output**: `policy_action` (`allow`/`alert`/`block`/`kill`), `policy_rule_id`, `mle_type`, `mle_confidence`

**EventsMatching temporal correlation format** (JSON):
```json
{
  "id": "mle.ransomware.mass_encrypt",
  "name": "Mass file encryption pattern",
  "threat_category": "ransomware",
  "confidence": 90,
  "action": "block",
  "sequence": [
    { "lle_type": "LLE_FILE_DELETE", "min_count": 10, "window_s": 5 },
    { "lle_type": "LLE_FILE_CREATE", "conditions": [{"field": "file.path", "op": "suffix_in", "value": [".encrypted", ".locked", ".crypt"]}], "min_count": 5 }
  ],
  "same_pid": true
}
```

#### Stage 5: get_fls_verdict — File Reputation Lookup

**Input fields consumed**: `file.hash_sha256`, `lle_type`, `policy_action`

**Fields added to output**: `fls.verdict` (`clean`/`malicious`/`unknown`), `fls.confidence`, `fls.threat_category`, `fls.family`

Verdict lookup is performed on the `SlowNetwork` lane. If the hash is in the local verdict cache, the lookup is completed in microseconds without a network call. If the verdict is `malicious`, the `policy_action` is upgraded to `block` regardless of the pattern-matching stage decision.

#### Stage 6: check_for_valkyrie — Dynamic Analysis Verdict

**Input fields consumed**: `fls.verdict`, `pattern_score`, `file.hash_sha256`, `file.path`

**Fields added to output**: `valkyrie.verdict`, `valkyrie.confidence`, `valkyrie.analysis_id`

Valkyrie submission is only triggered when: the FLS verdict is `unknown` AND the pattern score exceeds a configurable threshold (default 60). The file is uploaded to the Valkyrie cloud sandbox. The pipeline does not block waiting for the verdict; instead, it proceeds with the available information and the Valkyrie verdict is applied when it arrives asynchronously, potentially triggering a retrospective alert.

#### Stage 7: output — Event Routing and Response

**Input fields consumed**: `policy_action`, `mle_type`, `mle_confidence`, all enriched fields

**Actions performed**:

| Condition | Action |
|---|---|
| `policy_action == "alert"` | Generate alert record; push to alert stream; upload to cloud |
| `policy_action == "block"` | Terminate originating process (`TerminateProcess`) or block file operation (via FilterPort response to minifilter) |
| `policy_action == "kill"` | Terminate process tree (all children via `ProcessDataProvider` hierarchy) |
| Always (non-excluded events) | Upload LLE + metadata to AWS Firehose for SIEM ingestion |
| `mle_type` set | Upload MLE record separately to cloud for threat intelligence correlation |

**Alert record format** (JSON):
```json
{
  "alert_id": "<uuid>",
  "timestamp": "<ISO8601>",
  "endpoint_id": "<enrollment-id>",
  "mle_type": "ransomware",
  "confidence": 90,
  "action_taken": "block",
  "process": {
    "pid": 4321,
    "image_path": "C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe",
    "cmdline": "payload.exe --encrypt",
    "username": "DOMAIN\\user",
    "hierarchy": ["payload.exe", "explorer.exe"]
  },
  "matched_rules": ["mle.ransomware.mass_encrypt", "rule.office.spawns.shell"],
  "fls_verdict": "malicious",
  "fls_family": "Ryuk"
}
```

#### Scenario File Structure

Each QSC scenario file (stored in `edrdata/scenarios/*.json`) describes the pipeline configuration for a specific detection scenario or event category. Files are loaded by `edrsvc` at startup and after policy updates. The `edrdata` directory also contains:

| Path | Contents |
|---|---|
| `edrdata/scenarios/` | JSON scenario files, one per detection theme |
| `edrdata/policies/` | Compiled and source policy rule sets |
| `edrdata/patterns/` | Reusable pattern libraries (process name sets, file extension sets) |
| `edrdata/schema/` | JSON Schema definitions for policy validation |
| `edrdata/exclusions/` | Default exclusion rule sets for known clean software |

---

*End of Section 2: Architecture & Component Reference*
# Section 3: Quick Start, Prerequisites, Build Instructions, Installation, Docker, and ELK Stack Integration

---

## Quick Start

OpenArmor can be deployed through three paths depending on your environment and requirements. Choose the path that best matches your use case.

| Deployment Path | Estimated Time | Best For |
|---|---|---|
| Cloud (Comodo Dragon) | 5 minutes | Evaluation, quick trials, managed deployments |
| Docker (ELK backend) | 15 minutes | Development, lab environments, self-hosted analytics |
| Native Windows Install | 30 minutes | Production endpoints, enterprise rollout |
| Build from Source | 2–4 hours | Contributors, custom builds, security audits |

### Path 1: Cloud — Comodo Dragon (5 Minutes)

The fastest way to get started with OpenArmor is through the Comodo Dragon cloud platform, which provides a fully managed backend with zero infrastructure setup.

1. Send an email to **quick-start@openedr.com** with the subject line `OpenArmor Cloud Onboarding Request`.
2. Include in the body: your organization name, number of endpoints, and preferred region (US, EU, APAC).
3. You will receive a welcome email within one business day containing:
   - Your tenant portal URL
   - Agent download link pre-configured with your tenant credentials
   - API key and endpoint ID
4. Download the pre-configured installer and run it on your Windows endpoints.
5. Events will appear in the Comodo Dragon portal within minutes of installation.

For enterprise licensing and SLA details, contact the OpenArmor team through the portal or email **enterprise@openedr.com**.

---

### Path 2: Docker ELK Backend (15 Minutes)

This path sets up a local ELK (Elasticsearch, Logstash, Kibana) stack in Docker to receive and visualize telemetry from OpenArmor agents running natively on Windows endpoints.

```bash
# Step 1: Clone the repository
git clone --recursive https://github.com/openarmor/openarmor.git
cd openarmor

# Step 2: Start the ELK stack
docker-compose up -d

# Step 3: Verify all services are healthy
docker-compose ps

# Step 4: Open Kibana in your browser
# http://localhost:5601
```

Then install the OpenArmor agent on your Windows endpoint (see [Native Install](#path-3-native-windows-install-30-minutes) below) and point its output to your Docker host IP.

Full Docker documentation: [Docker Deployment](#docker-deployment)

---

### Path 3: Native Windows Install (30 Minutes)

1. Download the latest installer from the [Releases page](https://github.com/ComodoSecurity/openedr/releases/tag/release-2.5.1).
2. Run `OpenArmor-Setup-x64.msi` as Administrator.
3. Follow the installation wizard.
4. Verify installation with `sc query OpenArmorEDR`.

Full installation documentation: [Installation Guide](#installation-guide)

---

### Path 4: Build from Source (2–4 Hours)

Building from source is required for contributors, security researchers, or organizations that require verified builds.

```cmd
git clone --recursive https://github.com/openarmor/openarmor.git
cd openarmor
git submodule update --init --recursive
# Open edrav2\build\vs2019\edrav2.sln in Visual Studio 2019
# Build solution in Release|x64 configuration
```

Full build documentation: [Build Instructions](#build-instructions)

---

## Prerequisites

Before proceeding, ensure your environment meets all prerequisites for your chosen deployment path. Failing to meet prerequisites is the most common cause of failed installations and build errors.

---

### Operating System Support

OpenArmor supports the following Windows versions. The kernel-mode driver (`edrdrv.sys`) requires a supported OS version; attempting to load the driver on unsupported versions will result in an `INVALID_OS_VERSION` load failure.

| Operating System | Version / Build | Architecture | WDK Target | Notes |
|---|---|---|---|---|
| Windows 10 | 1903 (Build 18362) or later | x64 only | 10.0.18362+ | Minimum supported; 1903 required for some ETW providers |
| Windows 10 | 21H2 (Build 19044) | x64 only | 10.0.19041+ | Recommended for development |
| Windows 10 | 22H2 (Build 19045) | x64 only | 10.0.19041+ | Latest Windows 10; fully supported |
| Windows 11 | 21H2 (Build 22000) | x64 only | 10.0.22000+ | Fully supported |
| Windows 11 | 22H2 (Build 22621) | x64 only | 10.0.22000+ | Recommended for new deployments |
| Windows 11 | 23H2 (Build 22631) | x64 only | 10.0.22000+ | Fully supported |
| Windows Server 2016 | Build 14393 | x64 only | 10.0.14393+ | Supported; LTSC channel |
| Windows Server 2019 | Build 17763 | x64 only | 10.0.17763+ | Recommended for server deployments |
| Windows Server 2022 | Build 20348 | x64 only | 10.0.20348+ | Fully supported; recommended for new server installs |

**Architecture Note:** OpenArmor is x64-only. 32-bit (x86) Windows is not supported. ARM64 support is not available in the current release.

**WDK Matching:** The WDK version used to build the driver must match the Windows SDK version installed. Version mismatches between the WDK and the target OS are a common source of driver loading failures.

---

### Development Prerequisites (Build from Source)

The following tools are required to build OpenArmor from source. All tools must be installed before opening the Visual Studio solution.

#### Visual Studio

One of the following Visual Studio versions is required:

**Visual Studio 2019 (Recommended)**
- Version: 16.x (any 16.x update)
- Download: [https://visualstudio.microsoft.com/vs/older-downloads/](https://visualstudio.microsoft.com/vs/older-downloads/)

**Visual Studio 2017 (Supported)**
- Version: 15.9 or later (15.9 is the final update for VS2017)
- Download: [https://visualstudio.microsoft.com/vs/older-downloads/](https://visualstudio.microsoft.com/vs/older-downloads/)

##### Required Workloads

During Visual Studio installation, select the following workloads in the Visual Studio Installer:

| Workload | Required | Notes |
|---|---|---|
| Desktop development with C++ | **Required** | Core C++ compiler, linker, standard library, ATL, MFC |
| Linux development with C++ | Optional | Only needed if cross-compiling or working on cross-platform components |

##### Required Individual Components

Within the Visual Studio Installer, under **Individual components**, ensure the following are checked:

For **Visual Studio 2019**:

| Component | Component ID | Notes |
|---|---|---|
| MSVC v142 – VS 2019 C++ x64/x86 build tools | `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` | Required |
| Windows 10 SDK (10.0.18362.0) | `Microsoft.VisualStudio.Component.Windows10SDK.18362` | Minimum; 10.0.19041.0 recommended |
| C++ ATL for latest v142 build tools (x86 & x64) | `Microsoft.VisualStudio.Component.VC.ATL` | Required for COM components |
| C++ MFC for latest v142 build tools (x86 & x64) | `Microsoft.VisualStudio.Component.VC.ATLMFC` | Required for installer UI |
| C++ CMake tools for Windows | `Microsoft.VisualStudio.Component.VC.CMake.Project` | Required for dependency builds |

For **Visual Studio 2017**:

| Component | Component ID | Notes |
|---|---|---|
| MSVC v141 – VS 2017 C++ x64/x86 build tools | `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` | Required |
| Windows 10 SDK (10.0.18362.0) | `Microsoft.VisualStudio.Component.Windows10SDK.18362` | Required |
| Visual C++ ATL for x86 and x64 | `Microsoft.VisualStudio.Component.VC.ATL` | Required |
| Visual C++ MFC for x86 and x64 | `Microsoft.VisualStudio.Component.VC.ATLMFC` | Required |

To verify your VS installation has the required components, open a **Developer Command Prompt** and run:

```cmd
cl.exe
```

You should see output beginning with `Microsoft (R) C/C++ Optimizing Compiler`. If `cl.exe` is not found, the C++ workload was not installed correctly.

---

#### Windows Driver Kit (WDK)

The WDK is required to build the kernel-mode driver (`edrdrv.sys`). The WDK version must match the Windows 10 SDK version installed with Visual Studio.

**Minimum version:** WDK 10.0.18362 (corresponding to Windows 10, version 1903)
**Recommended version:** WDK 10.0.19041 (corresponding to Windows 10, version 2004)

**Download URL pattern:**

```
https://go.microsoft.com/fwlink/?linkid=2128854
```

WDK download links are version-specific. Navigate to the [WDK download archive](https://docs.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads) and download the WDK version that matches your installed Windows 10 SDK.

**Version Matching Instructions:**

1. Open Visual Studio Installer and note the Windows 10 SDK version under **Installed** > your VS version > **Individual components**.
2. Find the matching WDK version in the archive. The build number (e.g., `10.0.18362`) must match exactly.
3. Install the WDK. During installation, ensure the **"Install Windows Driver Kit Visual Studio extension"** checkbox is selected. This installs the VS integration that enables driver project types.
4. After WDK installation, reopen Visual Studio. Under **Extensions**, verify "Windows Driver Kit" appears as an installed extension.

**Verify WDK installation:**

Open a **Developer Command Prompt for VS 2019** and run:

```cmd
echo %WindowsSdkDir%
dir "%WindowsSdkDir%\Include\wdf"
```

You should see WDF header directories listed.

---

#### Git with LFS Support

Git 2.x or later is required. Git Large File Storage (LFS) must be installed for binary dependencies stored in LFS.

**Install Git:** [https://git-scm.com/download/win](https://git-scm.com/download/win)

After installing Git, install and initialize LFS:

```bash
# Install Git LFS (if not already installed via Git for Windows)
git lfs install

# Verify
git lfs version
```

Expected output: `git-lfs/3.x.x (GitHub; windows amd64; go 1.x.x)`

If Git LFS is not initialized before cloning, binary files (pre-built third-party libraries, test fixtures) will appear as LFS pointer files rather than actual binaries, causing build failures.

---

#### CMake

CMake 3.14 or later is required for building some third-party dependencies that use CMake-based build systems.

**Install CMake:** [https://cmake.org/download/](https://cmake.org/download/)

During installation, select **"Add CMake to the system PATH for all users"**.

**Verify:**

```cmd
cmake --version
```

Expected output: `cmake version 3.x.x`

---

#### Python 3.x

Python 3.6 or later is required for build helper scripts.

**Install Python:** [https://www.python.org/downloads/](https://www.python.org/downloads/)

During installation, select **"Add Python to PATH"**.

**Verify:**

```cmd
python --version
pip --version
```

---

### Runtime Prerequisites

These are required on any Windows endpoint where the OpenArmor agent will be installed, regardless of whether the host is a development machine or a production endpoint.

#### Administrator Privileges

Service installation and kernel driver loading require local Administrator rights. The installation wizard will prompt for UAC elevation. For silent/MSI installation, the process must be run from an elevated command prompt:

```cmd
# Open an elevated command prompt (Run as Administrator)
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart
```

#### Windows Driver Signature Enforcement

All kernel-mode drivers must be signed to load on modern Windows. OpenArmor ships two build types:

| Build Type | Signing Requirement | Use Case |
|---|---|---|
| Release (production) | EV Code Signing Certificate from a trusted CA | Production endpoints |
| Development (debug) | Self-signed certificate with test signing mode enabled | Development machines only |

**For development builds**, enable test signing mode:

```cmd
# Enable test signing (requires elevated prompt, triggers restart)
bcdedit /set testsigning on

# Restart the machine for the change to take effect
shutdown /r /t 0
```

> **Security Warning:** Test signing mode weakens the security of the machine by allowing unsigned drivers to load. Only enable this on dedicated development machines, never on production systems.

**For production builds**, the driver must be signed with an Extended Validation (EV) Code Signing Certificate issued by a CA in Microsoft's Trusted Root Program (e.g., DigiCert, Sectigo, GlobalSign). See [Driver Signing](#driver-signing) for full instructions.

#### .NET Framework 4.7.2+

The installer UI requires .NET Framework 4.7.2 or later. On Windows 10 version 1803 and later, .NET Framework 4.7.2 is included in the OS and requires no additional installation.

**Check installed version:**

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release
```

A value of `461808` or higher indicates .NET Framework 4.7.2 or later.

---

## Cloning the Repository

OpenArmor uses Git submodules extensively to manage third-party dependencies. Cloning without `--recursive` will result in missing source trees that cause immediate build failures.

### Full Clone (Recommended)

```bash
git clone --recursive https://github.com/openarmor/openarmor.git
cd openarmor
git submodule update --init --recursive
```

The `--recursive` flag causes Git to automatically initialize and clone all submodules defined in `.gitmodules`. After the initial clone, running `git submodule update --init --recursive` again ensures all nested submodules (submodules within submodules) are also initialized.

### Why `--recursive` Is Required

The OpenArmor repository depends on the following third-party libraries, each managed as a Git submodule in the `edrav2/eprj/` directory:

| Submodule | Path | Purpose |
|---|---|---|
| Boost | `edrav2/eprj/boost` | Core utility libraries (filesystem, asio, json, etc.) |
| OpenSSL | `edrav2/eprj/openssl` | TLS/SSL support for secure communications |
| gRPC | `edrav2/eprj/grpc` | Remote procedure call framework for agent-server comms |
| Protocol Buffers | `edrav2/eprj/protobuf` | Serialization for event data structures |
| AWS SDK for C++ | `edrav2/eprj/awssdkcpp` | S3 and cloud integration support |
| Microsoft Detours | `edrav2/eprj/detours` | API hooking library used by the user-mode agent |
| Crashpad | `edrav2/eprj/crashpad` | Crash reporting and minidump collection |
| nlohmann/json | `edrav2/eprj/nlohmann` | JSON parsing and serialization |
| libcurl | `edrav2/eprj/curl` | HTTP client for telemetry upload |
| zlib | `edrav2/eprj/zlib` | Compression for log shipping |

Without these submodules, the Visual Studio solution will fail to find include files and static libraries, generating hundreds of `C1083` (cannot open include file) and `LNK1181` (cannot open input file) errors.

### Verifying the Clone

After cloning, verify the submodules are populated:

```bash
# Check submodule status — all entries should show a commit hash, not '-'
git submodule status

# Verify key dependency directories are not empty
ls edrav2/eprj/boost/
ls edrav2/eprj/openssl/
ls edrav2/eprj/grpc/
```

If any submodule shows `- <commit-hash>` (with a leading dash), it has not been initialized. Run:

```bash
git submodule update --init --recursive
```

### Shallow Clone (Not Recommended)

Shallow clones (`--depth 1`) are not recommended because several third-party dependencies require full Git history for their own build scripts to determine version numbers. If you must use a shallow clone for bandwidth reasons:

```bash
git clone --recursive --shallow-submodules https://github.com/openarmor/openarmor.git
cd openarmor
git submodule update --init --recursive
```

Be aware that you may encounter build errors in dependencies that introspect their own Git history.

---

## Build Instructions

All build paths assume the repository has been fully cloned with submodules initialized (see [Cloning the Repository](#cloning-the-repository)).

**Before building**, ensure the following are installed and on your PATH:
- Visual Studio 2017 (15.9+) or Visual Studio 2019 (16.x+) with required components
- Windows Driver Kit (WDK) matching your Windows SDK version
- Git with LFS
- CMake 3.14+
- Python 3.x

---

### Visual Studio 2019 (Recommended)

#### Step 1: Open the Solution

Open Visual Studio 2019, then open the solution file:

```
edrav2\build\vs2019\edrav2.sln
```

Alternatively, from the command line:

```cmd
start edrav2\build\vs2019\edrav2.sln
```

Visual Studio will scan and load all projects in the solution. This may take 30–60 seconds on first open as IntelliSense indexes the codebase.

#### Step 2: Configure Build Target

In the Visual Studio toolbar, set the **Solution Configuration** and **Solution Platform** dropdowns:

- **Configuration:** `Release` (for production builds) or `Debug` (for development and debugging)
- **Platform:** `x64` (the only supported platform)

> **Note:** The `Debug` configuration builds without optimizations and includes full debug symbols. Use `Release` for performance testing and production builds. Never ship `Debug` builds to production endpoints.

#### Step 3: Build Order (Dependencies First)

The solution is configured with project dependencies that should handle build ordering automatically. However, if you encounter linker errors on a first build, build projects in the following order:

1. **Third-party libraries** (build automatically as dependencies)
   - `boost_*` projects
   - `openssl`
   - `protobuf`
   - `grpc`
   - `curl`
   - `zlib`
   - `detours`
   - `crashpad`

2. **Core infrastructure**
   - `libcore` — Core utility library shared by all components
   - `libmsg` — Message passing infrastructure

3. **Agent components**
   - `edrdrv` — Kernel-mode driver
   - `edrpm` — Process monitor DLL (injected into processes)
   - `edrmm` — Memory manager DLL
   - `edrext` — Extension DLL

4. **Service and utilities**
   - `edrsvc` — Main EDR service
   - `edrcon` — Console control utility

5. **Tests** (optional)
   - `ReferenceTests` — Unit and integration test suite

To build the entire solution at once:

- **Menu:** Build → Build Solution (`Ctrl+Shift+B`)

To build a specific project:
- Right-click the project in **Solution Explorer** → **Build**

#### Step 4: Output Locations

Build outputs are placed in the following directory structure:

```
edrav2\build\vs2019\x64\Release\
  edrsvc.exe          # Main EDR service — runs as a Windows service
  edrcon.exe          # Command-line control utility
  edrdrv.sys          # Kernel-mode driver — loaded by edrsvc.exe
  edrpm.dll           # Process monitor DLL — injected into monitored processes
  edrmm.dll           # Memory manager DLL
  edrext.dll          # Extension DLL — additional monitoring capabilities
  libcore.dll         # Core shared library (runtime dependency)
  edrsvc.pdb          # PDB symbols for edrsvc.exe (keep for crash analysis)
  edrdrv.pdb          # PDB symbols for edrdrv.sys
  edrcon.pdb          # PDB symbols for edrcon.exe
```

For `Debug` builds, the path is:

```
edrav2\build\vs2019\x64\Debug\
```

#### Step 5: Copying Build Artifacts

After a successful build, copy the output files to your deployment directory:

```cmd
set BUILD_OUT=edrav2\build\vs2019\x64\Release
set DEPLOY_DIR=C:\OpenArmor

mkdir "%DEPLOY_DIR%"
copy "%BUILD_OUT%\edrsvc.exe"  "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\edrcon.exe"  "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\edrdrv.sys"  "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\edrpm.dll"   "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\edrmm.dll"   "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\edrext.dll"  "%DEPLOY_DIR%\"
copy "%BUILD_OUT%\libcore.dll" "%DEPLOY_DIR%\"
```

---

### Visual Studio 2017

The VS2017 build process is identical to VS2019 except for the solution file path.

#### Step 1: Open the Solution

```
edrav2\build\vs2017\edrav2.sln
```

```cmd
start edrav2\build\vs2017\edrav2.sln
```

#### Step 2: Configure Build Target

Set **Configuration** to `Release` and **Platform** to `x64` in the toolbar.

The VS2017 solution uses the **v141** toolchain (MSVC v141). If you have VS2019 installed but want to use VS2017 project files, ensure the v141 toolchain is installed in VS2019 (it is available as an optional component: **MSVC v141 – VS 2017 C++ x64/x86 build tools**).

#### Step 3: Build

Build → Build Solution (`Ctrl+Shift+B`)

#### Step 4: Output Location

```
edrav2\build\vs2017\x64\Release\
  edrsvc.exe
  edrcon.exe
  edrdrv.sys
  edrpm.dll
  edrmm.dll
  edrext.dll
  libcore.dll
```

---

### Command Line Build

For CI/CD pipelines and automated builds, use the provided `builder.cmd` script:

```cmd
cd edrav2\build\buildpipe
builder.cmd Release x64
```

#### builder.cmd Parameters

```
builder.cmd <Configuration> <Platform> [Options]

Parameters:
  Configuration    Build configuration: Release or Debug
  Platform         Target platform: x64 (only supported value)

Options:
  /notests         Skip building the test projects
  /noclean         Skip cleaning before building (incremental build)
  /log <path>      Write build log to <path> (default: build.log in buildpipe dir)
  /vs2017          Force use of VS2017 toolchain (default: auto-detect)
  /vs2019          Force use of VS2019 toolchain (default: auto-detect)

Examples:
  builder.cmd Release x64
  builder.cmd Debug x64 /notests
  builder.cmd Release x64 /log C:\Logs\openarmor-build.log
```

#### Environment Setup

The `builder.cmd` script automatically:
1. Detects the Visual Studio installation using `vswhere.exe`
2. Sets up the VS Developer environment (equivalent to opening a Developer Command Prompt)
3. Invokes `msbuild.exe` with the appropriate solution file, configuration, and platform
4. Copies build outputs to the `buildpipe\output\` directory

If `builder.cmd` cannot find Visual Studio, ensure VS is installed and `vswhere.exe` is available at:

```
C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
```

#### Build Output from builder.cmd

Artifacts are collected in:

```
edrav2\build\buildpipe\output\Release\x64\
  edrsvc.exe
  edrcon.exe
  edrdrv.sys
  edrpm.dll
  edrmm.dll
  edrext.dll
  libcore.dll
```

A build log is written to:

```
edrav2\build\buildpipe\build.log
```

---

### Building Individual Components

#### Building Only the Kernel Driver

```cmd
# From Developer Command Prompt for VS 2019
msbuild edrav2\build\vs2019\edrav2.sln /t:edrdrv /p:Configuration=Release /p:Platform=x64
```

Output: `edrav2\build\vs2019\x64\Release\edrdrv.sys`

#### Building Only the Service

```cmd
msbuild edrav2\build\vs2019\edrav2.sln /t:edrsvc /p:Configuration=Release /p:Platform=x64
```

This will also build all projects that `edrsvc` depends on (libcore, libmsg, etc.).

#### Building Only the Console Utility

```cmd
msbuild edrav2\build\vs2019\edrav2.sln /t:edrcon /p:Configuration=Release /p:Platform=x64
```

#### Building Only the Tests

```cmd
msbuild edrav2\build\vs2019\edrav2.sln /t:ReferenceTests /p:Configuration=Release /p:Platform=x64
```

---

### Driver Signing

The kernel driver (`edrdrv.sys`) must be code-signed to load on modern Windows. Unsigned drivers are blocked by default since Windows Vista 64-bit.

#### Option A: Test Signing Mode (Development Only)

Test signing mode allows self-signed driver certificates to be trusted. **Never enable this on production systems.**

**Step 1: Enable test signing mode**

```cmd
# Open Command Prompt as Administrator
bcdedit /set testsigning on
```

**Step 2: Restart the machine**

```cmd
shutdown /r /t 0
```

After restart, you will see a "Test Mode" watermark in the lower-right corner of the desktop.

**Step 3: Create a self-signed certificate**

```cmd
# Create a test certificate (Developer Command Prompt as Administrator)
makecert -r -pe -ss PrivateCertStore -n "CN=OpenArmor Test Cert" OpenArmorTest.cer

# Import the certificate into the Trusted Root store
certmgr /add OpenArmorTest.cer /s /r localMachine root

# Import into Trusted Publishers store
certmgr /add OpenArmorTest.cer /s /r localMachine trustedpublisher
```

**Step 4: Sign the driver with the test certificate**

```cmd
signtool sign /v /s PrivateCertStore /n "OpenArmor Test Cert" /fd sha256 /t http://timestamp.digicert.com edrdrv.sys
```

**Step 5: Verify signing**

```cmd
signtool verify /v /pa edrdrv.sys
sigcheck -nobanner edrdrv.sys
```

#### Option B: Production Signing (Release Builds)

Production builds require an Extended Validation (EV) Code Signing Certificate from a CA in Microsoft's Trusted Root Program.

**Requirements:**
- EV Code Signing Certificate from DigiCert, Sectigo, GlobalSign, or equivalent
- Physical hardware security key (HSM) as required by EV certificate policy
- Certificate must be in the `WHQL` (Windows Hardware Quality Lab) trusted store for kernel drivers, or you must submit the driver for WHQL certification

**Sign the driver:**

```cmd
# Sign with EV certificate (the /a flag auto-selects the best certificate)
signtool sign /a /fd sha256 /tr http://timestamp.digicert.com /td sha256 edrdrv.sys

# Alternatively, specify the certificate by thumbprint
signtool sign /sha1 <certificate-thumbprint> /fd sha256 /tr http://timestamp.digicert.com /td sha256 edrdrv.sys
```

**Verify the production signature:**

```cmd
# Verify the driver signature
signtool verify /v /pa edrdrv.sys

# Use sigcheck (Sysinternals) for detailed certificate chain verification
sigcheck -nobanner -a edrdrv.sys

# Check that the driver loads (on a test machine)
sc create TestEDRDrv type= kernel binPath= "C:\path\to\edrdrv.sys"
sc start TestEDRDrv
sc query TestEDRDrv
sc stop TestEDRDrv
sc delete TestEDRDrv
```

**WHQL Submission (Optional but Recommended):**

For the highest level of trust, submit the signed driver to the [Windows Hardware Developer Center](https://partner.microsoft.com/en-us/dashboard/hardware/search) for WHQL certification. WHQL-certified drivers load without any warnings on all Windows systems.

---

### Building Tests

OpenArmor includes a test suite (`ReferenceTests`) that validates core functionality. Tests are built as part of the main solution or independently.

#### Building the Test Project

```cmd
# Via MSBuild
msbuild edrav2\build\vs2019\edrav2.sln /t:ReferenceTests /p:Configuration=Release /p:Platform=x64

# Or open the solution in Visual Studio and right-click ReferenceTests → Build
```

#### Running Tests from Visual Studio

1. Open `edrav2\build\vs2019\edrav2.sln`
2. In the **Test** menu, select **Configure Run Settings** → **Select Solution Wide runsettings File**
3. Select: `edrav2\build\vs2019\ReferenceTests.runsettings`
4. Open **Test Explorer** (**Test** → **Test Explorer**)
5. Click **Run All Tests**

The `.runsettings` file configures test working directory, timeout, and test data paths.

#### Running Tests from Command Line

```cmd
# Using vstest.console.exe (included with Visual Studio)
vstest.console.exe edrav2\build\vs2019\x64\Release\ReferenceTests.dll /Settings:edrav2\build\vs2019\ReferenceTests.runsettings

# With verbose output
vstest.console.exe edrav2\build\vs2019\x64\Release\ReferenceTests.dll /Settings:edrav2\build\vs2019\ReferenceTests.runsettings /logger:console;verbosity=detailed

# Run specific test category
vstest.console.exe edrav2\build\vs2019\x64\Release\ReferenceTests.dll /TestCaseFilter:"Category=Unit"
```

#### Test Output

Test results are written to:

```
edrav2\build\vs2019\TestResults\
  <timestamp>\
    *.trx      # Test result XML files (importable into Azure DevOps, etc.)
```

---

### Troubleshooting Build Issues

#### WDK Version Mismatch

**Symptom:** Error `C1083: Cannot open include file: 'wdm.h'` or `LNK1181: cannot open input file 'BufferOverflowFastFailK.lib'`

**Cause:** The WDK version does not match the Windows 10 SDK version installed with Visual Studio.

**Fix:**
1. Open Visual Studio Installer → Modify → Individual Components
2. Note the exact Windows 10 SDK version installed (e.g., `10.0.19041.0`)
3. Download the exact matching WDK from [https://docs.microsoft.com/windows-hardware/drivers/other-wdk-downloads](https://docs.microsoft.com/windows-hardware/drivers/other-wdk-downloads)
4. Install the WDK and ensure the VS extension is also installed
5. Restart Visual Studio and rebuild

---

#### Missing SDK Components

**Symptom:** Error `MSB8036: The Windows SDK version X.X.X.X was not found.`

**Fix:**

```cmd
# Open Developer Command Prompt and check installed SDKs
reg query "HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
```

If the required SDK is missing, open Visual Studio Installer → Modify → Individual Components → select the required Windows 10 SDK version.

---

#### Boost Compilation Errors

**Symptom:** Errors during Boost header parsing such as `error C2589: '(': illegal token on right side of '::'`

**Cause:** Boost headers conflict with Windows macros (`min`, `max`). This is usually caused by incorrect include order.

**Fix:** Ensure `NOMINMAX` is defined before any Windows headers are included. This is set in the project's preprocessor definitions. Verify in project properties:

```
Project Properties → C/C++ → Preprocessor → Preprocessor Definitions
Should contain: NOMINMAX;WIN32_LEAN_AND_MEAN
```

If the error is in a specific Boost component, check if the submodule is correctly initialized:

```bash
git submodule update --init edrav2/eprj/boost
```

---

#### OpenSSL Build Failures

**Symptom:** Errors during OpenSSL build: `'OPENSSL_EXPORT' was not declared in this scope` or NASM-related errors.

**Cause:** OpenSSL builds require NASM (Netwide Assembler) for assembly optimizations on x64.

**Fix:**
1. Install NASM: [https://www.nasm.us/pub/nasm/releasebuilds/](https://www.nasm.us/pub/nasm/releasebuilds/)
2. Add NASM to PATH: `C:\Program Files\NASM\`
3. Restart VS/build environment and retry

Verify NASM is accessible:

```cmd
nasm --version
```

---

#### Driver Signing Errors

**Symptom:** `SignTool Error: No certificates were found that met all the given criteria.`

**Fix for test signing:**
```cmd
# Verify the certificate exists in PrivateCertStore
certmgr /s PrivateCertStore

# If empty, recreate the test certificate (see Driver Signing section)
```

**Symptom:** `The driver could not be loaded. Error: 577 — Windows cannot verify the digital signature for this file.`

**Fix:**
```cmd
# Verify test signing is enabled
bcdedit /enum | findstr "testsigning"
# Should show: testsigning          Yes

# If not, enable it and restart
bcdedit /set testsigning on
shutdown /r /t 0
```

---

## Installation Guide

<picture>
  <source srcset="assets/Windows_installer_wizard_splash_…_202605010255.avif" type="image/avif">
  <img src="assets/Windows_installer_wizard_splash_…_202605010255.avif" alt="OpenArmor Installer Wizard" width="100%">
</picture>

The OpenArmor installer deploys all components: the kernel driver, EDR service, console utility, and default configuration files. The installer requires Administrator privileges and will prompt for UAC elevation.

---

### Download

**Latest Release: 2.5.1**

Download from: [https://github.com/ComodoSecurity/openedr/releases/tag/release-2.5.1](https://github.com/ComodoSecurity/openedr/releases/tag/release-2.5.1)

| File | Size | Description |
|---|---|---|
| `OpenArmor-Setup-x64.msi` | ~45 MB | Windows Installer package — recommended for enterprise deployment and GPO distribution |
| `OpenArmor-Setup-x64.exe` | ~48 MB | Self-extracting bootstrapper with .NET prerequisite check — recommended for individual installations |
| `edrav2-release-2.5.1.zip` | ~42 MB | Manual installation archive — all binaries without installer; for custom deployments |

**Verify download integrity** (SHA-256 checksums published on the releases page):

```cmd
# PowerShell
Get-FileHash OpenArmor-Setup-x64.msi -Algorithm SHA256
```

Compare the output against the checksum listed on the GitHub release page.

---

### Silent Installation

Silent installation is suitable for enterprise deployment via SCCM, Intune, or similar management platforms.

#### Basic Silent Install (Default Configuration)

```cmd
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart
```

This installs to the default directory (`C:\Program Files\OpenArmor\`) with default configuration.

#### Silent Install with Custom Parameters

```cmd
# Silent install with custom install directory and configuration file
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart INSTALLDIR="C:\OpenArmor" CONFIG="C:\config\edrsvc.json"

# Silent install with logging (for troubleshooting)
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart /log C:\Logs\openarmor-install.log

# Silent install with verbose logging
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart /l*v C:\Logs\openarmor-install-verbose.log
```

#### MSI Properties Reference

| Property | Default | Description |
|---|---|---|
| `INSTALLDIR` | `C:\Program Files\OpenArmor\` | Installation directory |
| `CONFIG` | `%INSTALLDIR%\edrsvc.json` | Path to configuration file |
| `STARTSERVICE` | `1` | `1` = start service after install, `0` = install only |
| `ADDLOCAL` | `ALL` | Features to install (`ALL` or comma-separated feature names) |

#### Silent Uninstall

```cmd
# Uninstall using MSI (preserves configuration files)
msiexec /x OpenArmor-Setup-x64.msi /quiet /norestart

# Uninstall by product code (when MSI file is not available)
# Find product code first:
msiexec /qn /l*v - /x {PRODUCT-CODE}

# PowerShell — find and uninstall
$app = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*OpenArmor*" }
$app.Uninstall()
```

---

### Manual Installation

For environments where the MSI installer cannot be used, or for custom deployment scenarios, install from the `edrav2-release-2.5.1.zip` archive.

#### Step 1: Extract Archive

```cmd
# Create installation directory
mkdir "C:\Program Files\OpenArmor"

# Extract using PowerShell
Expand-Archive -Path edrav2-release-2.5.1.zip -DestinationPath "C:\Program Files\OpenArmor\" -Force
```

Expected directory structure after extraction:

```
C:\Program Files\OpenArmor\
  edrsvc.exe
  edrcon.exe
  edrdrv.sys
  edrpm.dll
  edrmm.dll
  edrext.dll
  libcore.dll
  edrsvc.json          # Default configuration
  edrdrv.cat           # Driver catalog file (for signing)
```

#### Step 2: Install the Kernel Driver

```cmd
# Create the driver service
sc create OpenArmorEDRDrv type= kernel start= demand binPath= "C:\Program Files\OpenArmor\edrdrv.sys" DisplayName= "OpenArmor EDR Driver"

# Start the driver
sc start OpenArmorEDRDrv

# Verify driver is running
sc query OpenArmorEDRDrv
```

Expected output from `sc query OpenArmorEDRDrv`:

```
SERVICE_NAME: OpenArmorEDRDrv
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

If the driver fails to start with error 577, see [Driver Signing Errors](#driver-signing-errors).

#### Step 3: Register the Service

```cmd
# Install edrsvc as a Windows service
cd "C:\Program Files\OpenArmor"
edrsvc.exe install

# Alternatively, register manually
sc create OpenArmorEDR type= own start= auto binPath= "\"C:\Program Files\OpenArmor\edrsvc.exe\" --service" DisplayName= "OpenArmor EDR Service" depend= OpenArmorEDRDrv
```

#### Step 4: Configure edrsvc.json

The main configuration file is `edrsvc.json` in the installation directory. Open it in a text editor and configure the following key settings:

```json
{
  "log": {
    "level": "info",
    "path": "C:\\ProgramData\\OpenArmor\\logs\\edrsvc.log",
    "maxSize": 104857600,
    "maxFiles": 10
  },
  "events": {
    "outputPath": "C:\\ProgramData\\OpenArmor\\logs\\events.json",
    "maxSize": 524288000
  },
  "network": {
    "sendEnabled": false,
    "endpoint": "https://your-backend-host:8443/api/events",
    "apiKey": "YOUR-API-KEY-HERE"
  },
  "monitoring": {
    "processCreation": true,
    "networkConnections": true,
    "fileSystem": true,
    "registry": true,
    "dnsRequests": true
  }
}
```

Create the required data directories:

```cmd
mkdir "C:\ProgramData\OpenArmor\logs"
mkdir "C:\ProgramData\OpenArmor\data"

# Set permissions (service runs as SYSTEM, but log directory needs write access)
icacls "C:\ProgramData\OpenArmor" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F"
```

#### Step 5: Start the Service

```cmd
net start OpenArmorEDR

# Or using sc
sc start OpenArmorEDR
```

---

### Post-Installation Verification

After installation (via MSI or manual), verify all components are running correctly.

#### Verify the Windows Service

```cmd
sc query OpenArmorEDR
```

Expected output:

```
SERVICE_NAME: OpenArmorEDR
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

#### Verify the Kernel Driver

```cmd
sc query OpenArmorEDRDrv
```

Expected `STATE: 4 RUNNING`.

#### Verify with edrcon Utility

```cmd
cd "C:\Program Files\OpenArmor"
edrcon dump
```

This outputs the current agent status, including:
- Driver connection state
- Monitoring subsystems enabled/disabled
- Event counts
- Configuration summary

#### Check Logs

```cmd
# Service log
type "C:\ProgramData\OpenArmor\logs\edrsvc.log"

# Events output (JSON events from monitored processes)
type "C:\ProgramData\OpenArmor\logs\events.json"

# PowerShell — tail the log (watch for new lines)
Get-Content "C:\ProgramData\OpenArmor\logs\edrsvc.log" -Wait -Tail 50
```

#### Generate a Test Event

```cmd
# Run a test process to generate a process creation event
cmd.exe /c whoami

# Check that the event appeared in events.json
type "C:\ProgramData\OpenArmor\logs\events.json" | findstr "whoami"
```

---

### Uninstallation

Before uninstalling, disable the self-protection feature (`edrcon unprot`) to allow the service to be stopped.

```cmd
# Step 1: Disable self-protection
cd "C:\Program Files\OpenArmor"
edrcon unprot

# Step 2: Stop the service
sc stop OpenArmorEDR

# Step 3: Delete the service
sc delete OpenArmorEDR

# Step 4: Stop the driver
sc stop OpenArmorEDRDrv

# Step 5: Delete the driver service
sc delete OpenArmorEDRDrv

# Step 6: Remove files (optional — preserves configuration)
rmdir /s /q "C:\Program Files\OpenArmor"

# Step 7: Remove data directory (optional — preserves logs)
rmdir /s /q "C:\ProgramData\OpenArmor"
```

If uninstalling via MSI:

```cmd
msiexec /x OpenArmor-Setup-x64.msi /quiet /norestart
```

---

## Docker Deployment

<picture>
  <source srcset="assets/OpenArmor_deployment_network_dia…_202605010256.avif" type="image/avif">
  <img src="assets/OpenArmor_deployment_network_dia…_202605010256.avif" alt="OpenArmor Deployment Architecture" width="100%">
</picture>

### Architecture

The Docker deployment provides the analytics backend for OpenArmor. The OpenArmor Windows agent (`edrsvc.exe`) runs natively on Windows endpoints and cannot run in Docker (it requires the Windows kernel driver). Docker is used to host the ELK stack that receives, processes, stores, and visualizes telemetry from those endpoints.

```
┌─────────────────────────────────────┐      ┌─────────────────────────────────┐
│  Windows Endpoint                   │      │  Docker Host (Linux/Windows)    │
│                                     │      │                                 │
│  ┌─────────────────┐                │      │  ┌──────────────────────────┐  │
│  │  edrdrv.sys     │  kernel events │      │  │  Elasticsearch           │  │
│  │  (kernel mode)  │──────────────► │      │  │  :9200                   │  │
│  └────────┬────────┘                │      │  └──────────────────────────┘  │
│           │                         │      │           ▲                     │
│  ┌────────▼────────┐                │      │  ┌────────┴─────────────────┐  │
│  │  edrsvc.exe     │  JSON events   │      │  │  Logstash                │  │
│  │  (user mode)    │──────────────► │      │  │  :5044 (Beats input)     │  │
│  └────────┬────────┘                │      │  └──────────────────────────┘  │
│           │ writes                  │      │           ▲                     │
│  ┌────────▼────────┐                │      │  ┌────────┴─────────────────┐  │
│  │  events.json    │                │      │  │  Filebeat                │  │
│  │  (log file)     │◄──────────────────────►  │  :5066                   │  │
│  └─────────────────┘  ships via     │      │  └──────────────────────────┘  │
│                        Filebeat     │      │                                 │
│                                     │      │  ┌──────────────────────────┐  │
│                                     │      │  │  Kibana                  │  │
│                                     │      │  │  :5601                   │  │
└─────────────────────────────────────┘      │  └──────────────────────────┘  │
                                             └─────────────────────────────────┘
```

In this architecture:
- **Filebeat** runs on the Windows endpoint (or the Docker host can pull logs via a shared volume in lab setups)
- **Logstash**, **Elasticsearch**, and **Kibana** run in Docker
- The Windows agent writes JSON events to disk; Filebeat ships those events to Logstash

---

### Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Docker Desktop | 4.0 | 4.x latest |
| Docker Engine (Linux) | 20.10 | 24.x |
| Docker Compose | 2.0 | 2.x latest |
| RAM (Docker host) | 8 GB | 16 GB |
| CPU cores | 2 | 4+ |
| Disk space | 50 GB | 200 GB |
| OS (Docker host) | Ubuntu 20.04 / Windows 10+ | Ubuntu 22.04 |

**Install Docker Desktop (Windows/Mac):**
- Download: [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)

**Install Docker Engine (Linux/Ubuntu):**

```bash
# Add Docker's official GPG key
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add your user to the docker group (avoid sudo for every command)
sudo usermod -aG docker $USER
newgrp docker
```

**Set vm.max_map_count (Linux only — required for Elasticsearch):**

```bash
# Set for current session
sudo sysctl -w vm.max_map_count=262144

# Set permanently (survives reboot)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

### Quick Start

```bash
# Step 1: Clone the repository (if not already cloned)
git clone https://github.com/openarmor/openarmor.git
cd openarmor

# Step 2: Start all ELK services
docker-compose up -d
```

After running `docker-compose up -d`, verify all services started:

```bash
docker-compose ps
```

![Docker Compose Up](assets/screenshots/docker-compose-allup.avif)

Expected output:

```
NAME                    IMAGE                   COMMAND                  SERVICE         STATUS          PORTS
openarmor-elasticsearch elasticsearch:8.x.x     "/bin/tini -- /usr/l…"   elasticsearch   running (healthy)   0.0.0.0:9200->9200/tcp
openarmor-logstash      logstash:8.x.x          "/usr/local/bin/dock…"   logstash        running         0.0.0.0:5044->5044/tcp
openarmor-kibana        kibana:8.x.x            "/bin/tini -- /usr/l…"   kibana          running (healthy)   0.0.0.0:5601->5601/tcp
openarmor-filebeat      elastic/filebeat:8.x.x  "/usr/bin/tini -- /u…"   filebeat        running
```

![Docker PS](assets/screenshots/docker-ps-list.avif)

Watch logs for Elasticsearch to confirm it is ready:

```bash
docker-compose logs -f elasticsearch
```

Wait until you see: `started` in the Elasticsearch log output, then press `Ctrl+C` to stop following.

Open Kibana in your browser: [http://localhost:5601](http://localhost:5601)

---

### docker-compose.yml Explained

The `docker-compose.yml` in the repository root defines four services:

#### Elasticsearch

```yaml
elasticsearch:
  image: elasticsearch:8.11.0
  container_name: openarmor-elasticsearch
  environment:
    - discovery.type=single-node          # Single-node cluster (dev/lab)
    - ES_JAVA_OPTS=-Xms2g -Xmx2g         # 2 GB JVM heap (adjust for your RAM)
    - xpack.security.enabled=false        # Disable authentication for dev
    - xpack.security.http.ssl.enabled=false
  volumes:
    - esdata:/usr/share/elasticsearch/data   # Persistent data volume
  ports:
    - "9200:9200"      # REST API — used by Kibana and direct queries
    - "9300:9300"      # Internal cluster communication (single-node: not needed externally)
  healthcheck:
    test: ["CMD-SHELL", "curl -f http://localhost:9200/_cluster/health || exit 1"]
    interval: 30s
    timeout: 10s
    retries: 10
  networks:
    - openarmor-net
```

**Key settings:**
- `discovery.type=single-node` — Disables the cluster formation process. Required for single-node development setups; remove this for multi-node production clusters.
- `ES_JAVA_OPTS=-Xms2g -Xmx2g` — Sets the JVM heap. `Xms` and `Xmx` should be equal to prevent heap resizing pauses. Set to 50% of available RAM, max 31 GB.
- `xpack.security.enabled=false` — Disables authentication. **Enable this for production.**

#### Logstash

```yaml
logstash:
  image: logstash:8.11.0
  container_name: openarmor-logstash
  volumes:
    - ./getting-started/logstash/pipeline:/usr/share/logstash/pipeline:ro   # Pipeline configs
    - ./getting-started/logstash/config:/usr/share/logstash/config:ro       # logstash.yml
  ports:
    - "5044:5044"      # Beats input — Filebeat ships to this port
    - "5000:5000"      # Optional: Syslog input (TCP)
    - "9600:9600"      # Logstash monitoring API
  environment:
    - LS_JAVA_OPTS=-Xms1g -Xmx1g
  depends_on:
    elasticsearch:
      condition: service_healthy
  networks:
    - openarmor-net
```

**Key settings:**
- Port `5044` is the Beats protocol input. Filebeat on Windows endpoints connects to this port.
- Pipeline configs are mounted from `./getting-started/logstash/pipeline/`. Modify these to customize parsing.
- `depends_on: elasticsearch: condition: service_healthy` — Logstash waits for Elasticsearch to pass its healthcheck before starting.

#### Kibana

```yaml
kibana:
  image: kibana:8.11.0
  container_name: openarmor-kibana
  environment:
    - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    - KIBANA_REPORTING_ENCRYPTION_KEY=a_long_random_string_at_least_32_chars
  ports:
    - "5601:5601"      # Kibana web UI
  depends_on:
    elasticsearch:
      condition: service_healthy
  healthcheck:
    test: ["CMD-SHELL", "curl -f http://localhost:5601/api/status || exit 1"]
    interval: 30s
    timeout: 10s
    retries: 10
  networks:
    - openarmor-net
```

#### Filebeat (Optional — For Lab Use)

In production, Filebeat runs on the Windows endpoint. For lab use with Docker-hosted log files:

```yaml
filebeat:
  image: elastic/filebeat:8.11.0
  container_name: openarmor-filebeat
  user: root
  volumes:
    - ./getting-started/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
    - /var/log/openarmor:/var/log/openarmor:ro    # Mount Windows log share (NFS/SMB)
  command: filebeat -e -strict.perms=false
  depends_on:
    - logstash
  networks:
    - openarmor-net
```

#### Named Volumes and Networks

```yaml
volumes:
  esdata:
    driver: local        # Persistent Elasticsearch data — survives container restarts

networks:
  openarmor-net:
    driver: bridge       # Internal Docker network for inter-service communication
```

---

### Production Docker Configuration

#### JVM Heap Sizing for Elasticsearch

The Elasticsearch JVM heap is configured via the `ES_JAVA_OPTS` environment variable. Rules:
- Set `Xms` and `Xmx` to the **same value** (prevents heap expansion pauses)
- Set to approximately **50% of available host RAM**
- **Never exceed 31 GB** (above this, JVM cannot use compressed object pointers, reducing efficiency)

| Host RAM | Recommended ES Heap |
|---|---|
| 8 GB | 4 GB (`-Xms4g -Xmx4g`) |
| 16 GB | 8 GB (`-Xms8g -Xmx8g`) |
| 32 GB | 16 GB (`-Xms16g -Xmx16g`) |
| 64 GB | 31 GB (`-Xms31g -Xmx31g`) |

#### Persistent Volumes for Production

For production, use named volumes with defined paths:

```yaml
volumes:
  esdata:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /data/elasticsearch       # Dedicated fast storage path

  logstash-logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /data/logstash/logs
```

#### Security for Production

Enable X-Pack security in Elasticsearch (disabled by default in the provided compose file):

```yaml
elasticsearch:
  environment:
    - xpack.security.enabled=true
    - xpack.security.http.ssl.enabled=true
    - xpack.security.transport.ssl.enabled=true
    - ELASTIC_PASSWORD=your_strong_password_here
```

Generate TLS certificates:

```bash
# Generate CA and node certificates using elasticsearch-certutil
docker exec -it openarmor-elasticsearch elasticsearch-certutil ca --out /usr/share/elasticsearch/config/elastic-stack-ca.p12 --pass ""
docker exec -it openarmor-elasticsearch elasticsearch-certutil cert --ca /usr/share/elasticsearch/config/elastic-stack-ca.p12 --ca-pass "" --out /usr/share/elasticsearch/config/elastic-certificates.p12 --pass ""
```

#### Log Rotation

```yaml
services:
  elasticsearch:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
```

---

### Scaling

#### Multi-Node Elasticsearch Cluster

For production workloads with high event volume, run a multi-node Elasticsearch cluster.

Example 3-node cluster (separate `docker-compose.prod.yml`):

```yaml
services:
  es01:
    image: elasticsearch:8.11.0
    environment:
      - node.name=es01
      - cluster.name=openarmor-cluster
      - discovery.seed_hosts=es02,es03
      - cluster.initial_master_nodes=es01,es02,es03
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
    volumes:
      - esdata01:/usr/share/elasticsearch/data

  es02:
    image: elasticsearch:8.11.0
    environment:
      - node.name=es02
      - cluster.name=openarmor-cluster
      - discovery.seed_hosts=es01,es03
      - cluster.initial_master_nodes=es01,es02,es03
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
    volumes:
      - esdata02:/usr/share/elasticsearch/data

  es03:
    image: elasticsearch:8.11.0
    environment:
      - node.name=es03
      - cluster.name=openarmor-cluster
      - discovery.seed_hosts=es01,es02
      - cluster.initial_master_nodes=es01,es02,es03
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
    volumes:
      - esdata03:/usr/share/elasticsearch/data
```

#### Logstash Pipeline Scaling

To handle higher event throughput, run multiple Logstash workers:

```yaml
logstash:
  environment:
    - pipeline.workers=4         # Number of parallel pipeline workers (default: CPU cores)
    - pipeline.batch.size=500    # Events per batch (increase for higher throughput)
    - pipeline.batch.delay=50    # Max milliseconds to wait for a full batch
```

For very high throughput, run multiple Logstash instances behind a load balancer, and configure Filebeat to use round-robin load balancing:

```yaml
output.logstash:
  hosts:
    - "logstash-01:5044"
    - "logstash-02:5044"
    - "logstash-03:5044"
  loadbalance: true
```

---

## ELK Stack Integration

<picture>
  <source srcset="assets/Data_pipeline_flow_diagram_202605010255.avif" type="image/avif">
  <img src="assets/Data_pipeline_flow_diagram_202605010255.avif" alt="ELK Data Pipeline" width="100%">
</picture>

### Pipeline Overview

The full data pipeline from endpoint event to Kibana visualization:

```
Windows Endpoint
  └── OpenArmor Agent (edrsvc.exe)
        │  monitors: process creation, network connections, file I/O,
        │            registry changes, DNS queries, memory operations
        └── writes JSON events to: C:\ProgramData\OpenArmor\logs\events.json
              └── Filebeat (ships to Logstash via Beats protocol)
                    └── Logstash (parse + enrich + normalize + filter)
                          │  - Grok pattern matching
                          │  - IP geolocation enrichment
                          │  - Timestamp normalization (UTC)
                          │  - Field type coercion
                          └── Elasticsearch (index + store + search)
                                │  - Index: openarmor-events-YYYY.MM.DD
                                │  - ILM: hot (7d) → warm (30d) → delete (90d)
                                └── Kibana (visualize + search + alert)
                                      - Pre-built EDR dashboards
                                      - Alert rules (SIEM)
                                      - Saved searches
                                      - Threat hunting workspace
```

---

### Setting Up Elasticsearch

For the full setup guide with detailed configuration options, see: `getting-started/SettingELK.md`

#### Step 1: Download and Install Elasticsearch

**Linux (Debian/Ubuntu):**

```bash
# Import the Elasticsearch GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add the Elasticsearch repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install
sudo apt-get update && sudo apt-get install elasticsearch

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
```

**Windows:**

```cmd
# Download the MSI installer from https://www.elastic.co/downloads/elasticsearch
# Run the installer as Administrator
# Or use the .zip archive for manual installation

# Using chocolatey
choco install elasticsearch

# Verify
curl http://localhost:9200
```

#### Step 2: elasticsearch.yml Configuration

The main configuration file is `/etc/elasticsearch/elasticsearch.yml` (Linux) or `config\elasticsearch.yml` (Windows).

Key settings for an OpenArmor deployment:

```yaml
# Cluster and node identity
cluster.name: openarmor-cluster
node.name: openarmor-node-01

# Data and log paths (Linux defaults)
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Network
network.host: 0.0.0.0        # Listen on all interfaces (adjust for production)
http.port: 9200

# Discovery (single-node development)
discovery.type: single-node

# Single-node production
cluster.initial_master_nodes: ["openarmor-node-01"]

# Security (for production — requires X-Pack)
xpack.security.enabled: false    # Set to true in production

# Index settings (defaults tuned for EDR events)
action.auto_create_index: true
indices.query.bool.max_clause_count: 8192
```

#### Step 3: JVM Options

Edit `/etc/elasticsearch/jvm.options` (Linux) or `config\jvm.options` (Windows):

```
# Heap size — set to 50% of available RAM, equal Xms and Xmx
-Xms4g
-Xmx4g

# GC settings (recommended for Elasticsearch 8.x)
## G1GC is the default and recommended GC
-XX:+UseG1GC
-XX:G1ReservePercent=25
-XX:InitiatingHeapOccupancyPercent=30

# Performance
-XX:+AlwaysPreTouch
```

#### Step 4: Index Templates for OpenArmor Events

Create a composable index template to ensure correct field mappings for OpenArmor event data:

```bash
# Create the index template
curl -X PUT "http://localhost:9200/_index_template/openarmor-events" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["openarmor-events-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s"
      },
      "mappings": {
        "properties": {
          "@timestamp":       { "type": "date" },
          "event.type":       { "type": "keyword" },
          "event.category":   { "type": "keyword" },
          "process.name":     { "type": "keyword" },
          "process.pid":      { "type": "long" },
          "process.command_line": { "type": "text" },
          "network.destination.ip":   { "type": "ip" },
          "network.destination.port": { "type": "integer" },
          "file.path":        { "type": "keyword" },
          "registry.key":     { "type": "keyword" },
          "host.name":        { "type": "keyword" },
          "host.ip":          { "type": "ip" },
          "agent.version":    { "type": "keyword" }
        }
      }
    },
    "priority": 500
  }'
```

#### Step 5: ILM Policy for Retention

Create an Index Lifecycle Management (ILM) policy to automatically roll over and delete old indices:

```bash
curl -X PUT "http://localhost:9200/_ilm/policy/openarmor-events-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "min_age": "0ms",
          "actions": {
            "rollover": {
              "max_primary_shard_size": "50gb",
              "max_age": "7d"
            },
            "set_priority": { "priority": 100 }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "shrink": { "number_of_shards": 1 },
            "forcemerge": { "max_num_segments": 1 },
            "set_priority": { "priority": 50 }
          }
        },
        "delete": {
          "min_age": "90d",
          "actions": {
            "delete": {}
          }
        }
      }
    }
  }'
```

#### Step 6: Verify Elasticsearch

```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# Check nodes
curl http://localhost:9200/_nodes?pretty

# List indices
curl http://localhost:9200/_cat/indices?v
```

---

### Setting Up Logstash

#### Step 1: Download and Install Logstash

**Linux (Debian/Ubuntu):**

```bash
# The elastic repository was added during Elasticsearch setup
sudo apt-get install logstash

sudo systemctl enable logstash
sudo systemctl start logstash
```

**Windows:**

```cmd
# Download from https://www.elastic.co/downloads/logstash
# Extract to C:\logstash\

# Run as a service
C:\logstash\bin\logstash-service.bat install
net start logstash
```

#### Step 2: Pipeline Configuration for OpenArmor Events

Create the pipeline configuration file at `/etc/logstash/conf.d/openarmor.conf` (Linux) or `C:\logstash\config\openarmor.conf` (Windows):

```ruby
# INPUT: Receive events from Filebeat (Beats protocol)
input {
  beats {
    port => 5044
    host => "0.0.0.0"
    # For TLS (production):
    # ssl => true
    # ssl_certificate => "/etc/logstash/certs/logstash.crt"
    # ssl_key => "/etc/logstash/certs/logstash.key"
    # ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
    # ssl_verify_mode => "force_peer"
  }
}

# FILTER: Parse, normalize, and enrich events
filter {
  # Parse JSON events from OpenArmor
  if [message] {
    json {
      source => "message"
      target => "openarmor"
    }
  }

  # Normalize timestamp
  if [openarmor][timestamp] {
    date {
      match => ["[openarmor][timestamp]", "ISO8601", "UNIX_MS", "UNIX"]
      target => "@timestamp"
    }
  }

  # Enrich IP addresses with geolocation
  if [openarmor][network][destination_ip] {
    geoip {
      source => "[openarmor][network][destination_ip]"
      target => "[openarmor][network][destination_geo]"
    }
  }

  # Map OpenArmor event types to ECS (Elastic Common Schema)
  if [openarmor][event_type] == "process_creation" {
    mutate {
      add_field => {
        "[event][category]" => "process"
        "[event][type]"     => "start"
        "[event][kind]"     => "event"
      }
    }
  }

  if [openarmor][event_type] == "network_connection" {
    mutate {
      add_field => {
        "[event][category]" => "network"
        "[event][type]"     => "connection"
      }
    }
  }

  if [openarmor][event_type] == "file_creation" or [openarmor][event_type] == "file_modification" {
    mutate {
      add_field => {
        "[event][category]" => "file"
        "[event][type]"     => "change"
      }
    }
  }

  # Remove redundant raw message field
  mutate {
    remove_field => ["message"]
  }
}

# OUTPUT: Write to Elasticsearch
output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "openarmor-events-%{+YYYY.MM.dd}"
    # For production with security enabled:
    # user => "logstash_writer"
    # password => "your_password"
    # ssl => true
    # cacert => "/etc/logstash/certs/ca.crt"
  }

  # Optional: stdout for debugging
  # stdout { codec => rubydebug }
}
```

#### Step 3: logstash.yml Configuration

![Logstash Config](assets/screenshots/logstashconfig-filebeatyml.avif)
![Logstash YAML](assets/screenshots/logstash-yaml.avif)

Edit `/etc/logstash/logstash.yml`:

```yaml
# Node identity
node.name: openarmor-logstash

# Pipeline settings
pipeline.workers: 4
pipeline.batch.size: 500
pipeline.batch.delay: 50

# HTTP monitoring API
http.host: "0.0.0.0"
http.port: 9600

# Logging
log.level: info
path.logs: /var/log/logstash
```

#### Step 4: Verify Logstash

```bash
# Test configuration
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/openarmor.conf

# Check Logstash status via monitoring API
curl http://localhost:9600/?pretty

# Check pipeline stats
curl http://localhost:9600/_node/stats/pipelines?pretty
```

---

### Setting Up Filebeat

Filebeat is the log shipper that runs on the Windows endpoint (where OpenArmor is installed) and ships the JSON event log to Logstash.

#### Step 1: Download Filebeat

![Install Filebeat 1](assets/screenshots/installing%20filebeat1.avif)
![Install Filebeat 2](assets/screenshots/installing%20file%20beat2.avif)

Download Filebeat for Windows from: [https://www.elastic.co/downloads/beats/filebeat](https://www.elastic.co/downloads/beats/filebeat)

**Important:** The Filebeat version must match the Logstash and Elasticsearch version. If running ELK 8.11, download Filebeat 8.11.

**Install on Windows:**

```powershell
# Download (PowerShell)
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-windows-x86_64.zip" -OutFile "filebeat.zip"

# Extract
Expand-Archive -Path filebeat.zip -DestinationPath "C:\filebeat"

# Install as a Windows service
cd C:\filebeat\filebeat-8.11.0-windows-x86_64
.\install-service-filebeat.ps1
```

If PowerShell execution policy blocks the script:

```powershell
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-filebeat.ps1
```

#### Step 2: Configure filebeat.yml

![Configure Inputs](assets/screenshots/filebeatinputs-filebeatyaml.avif)

The main configuration file is `C:\filebeat\filebeat-8.11.0-windows-x86_64\filebeat.yml`.

Replace the default contents with:

```yaml
# ==================== Filebeat inputs ====================
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - C:\ProgramData\OpenArmor\logs\events.json
    # Parse JSON events (OpenArmor writes one JSON object per line)
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: message
    # Multiline — disable if events are strictly one-per-line
    # multiline.pattern: '^{'
    # multiline.negate: true
    # multiline.match: after

    # Tagging
    tags: ["openarmor", "edr", "windows"]

    # Fields added to every event
    fields:
      agent_type: openarmor
      datacenter: primary
    fields_under_root: true

    # Harvester settings
    close_inactive: 5m
    scan_frequency: 10s
    harvester_buffer_size: 16384

# ==================== Outputs ====================
# Send to Logstash (recommended — enables pipeline processing)
output.logstash:
  hosts: ["your-logstash-host:5044"]
  # Load balancing (for multiple Logstash nodes)
  # loadbalance: true
  # worker: 2
  # For TLS:
  # ssl.certificate_authorities: ["C:\\filebeat\\ca.crt"]
  # ssl.certificate: "C:\\filebeat\\filebeat.crt"
  # ssl.key: "C:\\filebeat\\filebeat.key"

# Alternative: Send directly to Elasticsearch (bypass Logstash)
# output.elasticsearch:
#   hosts: ["http://your-elasticsearch-host:9200"]
#   index: "openarmor-events-%{+yyyy.MM.dd}"

# ==================== Logging ====================
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\filebeat\logs
  name: filebeat
  keepfiles: 7
  permissions: 0644

# ==================== Kibana ====================
# Used for setting up dashboards
setup.kibana:
  host: "http://your-kibana-host:5601"
```

Replace `your-logstash-host` with the IP address or hostname of your Logstash/Docker host.

#### Step 3: Enable the Logstash Module

![Enable Module](assets/screenshots/filebeat-enable-module-logstash.avif)
![Configure Modules](assets/screenshots/filebeatmodules-filebeatyaml.avif)

```cmd
cd C:\filebeat\filebeat-8.11.0-windows-x86_64

# List available modules
.\filebeat.exe modules list

# Enable the logstash module (for shipping Logstash logs as well)
.\filebeat.exe modules enable logstash
```

#### Step 4: Set Up Kibana Dashboards

```cmd
# Set up index patterns and dashboards in Kibana
.\filebeat.exe setup --dashboards
```

This command connects to Kibana (using the `setup.kibana.host` setting) and imports pre-built dashboards for monitoring Filebeat itself.

#### Step 5: Test the Configuration

```cmd
# Test filebeat.yml for syntax errors
.\filebeat.exe test config -e

# Test connectivity to Logstash
.\filebeat.exe test output -e
```

Expected output from `test output`:

```
logstash: your-logstash-host:5044...
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 192.168.1.10
    dial up... OK
  TLS... WARN secure connection disabled
  talk to server... OK
```

#### Step 6: Start and Verify Filebeat

![Service Restart](assets/screenshots/filebeat-service-restart.avif)
![Services Restart](assets/screenshots/services-filebeat-restart.avif)

```cmd
# Start via services
net start filebeat

# Or restart if already running
net stop filebeat
net start filebeat

# Check status
sc query filebeat
```

Monitor Filebeat logs to confirm it is shipping events:

```powershell
Get-Content "C:\ProgramData\filebeat\logs\filebeat" -Wait -Tail 50
```

Look for log lines like:

```
INFO    [publisher_pipeline_output] pipeline/output.go:154  Connection to backoff(async(tcp://your-logstash-host:5044)) established
INFO    [monitoring]                log/log.go:145  Non-zero metrics in the last 30s  {"monitoring": {"metrics": {"beat":{"cpu":...}, "filebeat":{"events":{"active":0,"added":150,"done":150}}}}}
```

The `"added":150,"done":150` indicates events are being shipped.

![Git Clone ELK](assets/screenshots/git-clone-elk.avif)

---

### Setting Up Kibana

For the full setup guide, see: `getting-started/SettingKibana.md`

#### Step 1: Access Kibana

Open your browser and navigate to:

```
http://your-kibana-host:5601
```

![Kibana UI 1](assets/screenshots/elastic%20ui1.avif)

On first launch, Kibana will display the welcome screen and prompt you to configure a data view (index pattern).

#### Step 2: Create an Index Pattern (Data View)

![Kibana UI 2](assets/screenshots/elastic%20ui2.avif)

1. In the left sidebar, click the **hamburger menu (☰)** → **Stack Management**
2. Under **Kibana**, click **Data Views**
3. Click **Create data view**
4. Configure:
   - **Name:** `OpenArmor Events`
   - **Index pattern:** `openarmor-events-*`
   - **Timestamp field:** `@timestamp`
5. Click **Save data view to Kibana**

![Kibana UI 3](assets/screenshots/elastic%20ui3.avif)

#### Step 3: Explore Data in Discover

1. Click **hamburger menu (☰)** → **Analytics** → **Discover**
2. Select the `OpenArmor Events` data view from the dropdown
3. Set the time range (top right) to the period when your endpoints were active
4. You should see OpenArmor events appearing in the results table

![Kibana UI 4](assets/screenshots/elastic%20ui4.avif)

#### Step 4: Import Pre-Built OpenArmor Dashboards

![Kibana UI 5](assets/screenshots/elastic%20ui5.avif)

Pre-built dashboards are included in the repository at `getting-started/kibana/`:

1. In Kibana, go to **Stack Management** → **Saved Objects**
2. Click **Import**
3. Select the dashboard export file: `getting-started/kibana/openarmor-dashboards.ndjson`
4. On the import screen, select **Overwrite** if prompted
5. Click **Import**

#### Step 5: Configure SIEM Alerts

![Kibana UI 6](assets/screenshots/elastic%20ui6.avif)

To set up alert rules for suspicious activity:

1. Go to **hamburger menu (☰)** → **Security** → **Rules**
2. Click **Create new rule**
3. Select rule type:
   - **Custom query** — for KQL-based alerts
   - **Threshold** — for frequency-based alerts (e.g., >10 failed logins in 5 minutes)
   - **Event correlation** — for multi-event sequence detection

Example rule: Alert on suspicious process creation from Office applications:

```
Rule name: Office App Spawning Shell
Rule type: Custom query
KQL query: event.category:"process" and process.parent.name:("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE") and process.name:("cmd.exe" or "powershell.exe" or "wscript.exe" or "cscript.exe")
Severity: High
Risk score: 73
```

#### Step 6: Saved Searches for Threat Hunting

![Kibana UI 7](assets/screenshots/elastic%20ui7.avif)

Create saved searches for common threat hunting queries:

**Lateral movement via PSExec:**

```kql
process.name: "PSEXESVC.exe" or process.command_line: *psexec*
```

**Persistence via registry run keys:**

```kql
event.category: "registry" and registry.key: (*\\CurrentVersion\\Run* or *\\CurrentVersion\\RunOnce*)
```

**DNS requests to unusual TLDs:**

```kql
event.category: "network" and dns.question.name: *.xyz or dns.question.name: *.tk or dns.question.name: *.ml
```

**Processes executing from temp directories:**

```kql
process.executable: (*\\AppData\\Local\\Temp\\* or *\\Windows\\Temp\\* or *\\Users\\Public\\*)
```

To save a search:
1. Enter the KQL query in Discover
2. Click **Save** (top right) → **Save search**
3. Give it a descriptive name
4. Check **Store time with saved search** if the time range is relevant

Saved searches appear in **Discover** → **Open** and can be added to dashboards.

---

*End of Section 3*
# Section 4: Policy Engine, Event Types Reference, MITRE ATT&CK Coverage, and Detection Examples

---

## Policy Engine

<picture>
  <source srcset="assets/Policy_engine_visualizing_event_…_202605010255.avif" type="image/avif">
  <img src="assets/Policy_engine_visualizing_event_…_202605010255.avif" alt="Policy Engine" width="100%">
</picture>

### Overview

The OpenArmor Policy Engine is the analytical core of the EDR platform, implementing a declarative, staged event-processing pipeline designed for high-throughput, low-latency threat detection on Windows endpoints. Rather than relying on monolithic detection logic, OpenArmor structures its detection pipeline as a series of independently configurable stages — each encapsulated in a **QSC (Queue-Scenario-Chain) scenario file** — that transform raw kernel-level telemetry into enriched, correlated, and prioritized security alerts.

At the heart of the design is the **Variant dictionary**: a strongly typed, schema-flexible data structure that carries event data between pipeline stages. Every low-level event (LLE) captured by the kernel driver is marshalled into a Variant dictionary and placed onto a named input queue. Scenario files consume from that queue, apply declarative transformation and filtering logic, and emit enriched dictionaries to a downstream output queue. This queue-based architecture decouples each processing stage, enabling independent tuning, replacement, and testing without disrupting the rest of the pipeline.

Key design principles:

- **Declarative configuration**: Detection logic is expressed in JSON-based scenario files, not compiled code. Security engineers can add, modify, or remove detection rules without recompiling the agent binary.
- **Staged enrichment**: Each stage adds context — process ancestry, file reputation, cloud sandbox verdicts — before the next stage evaluates detection conditions. This eliminates redundant lookups and ensures every detection has maximum context at alert time.
- **Queue isolation**: Named queues decouple producers from consumers. If one stage experiences a backlog, upstream stages are not stalled, and internal telemetry tracks queue depth and processing latency per stage.
- **Live policy updates**: The engine supports hot-swapping policy files via the `CloudConfigurationIsChanged` internal message, allowing policy updates to be pushed from a management server and applied in seconds without restarting the agent.
- **Composable logic**: Pattern rules, list references, and event conditions are all composable via logical operators, enabling complex multi-field, multi-event correlation without custom code.

The pipeline processes events in a strict linear sequence: raw kernel events enter at Stage 1 and, if not dropped by filtering or whitelist logic, flow through all subsequent stages before being routed to cloud or local storage at Stage 7. Stages that make external calls (FLS reputation, Valkyrie cloud sandbox) operate asynchronously to avoid blocking the pipeline on network latency.

---

### QSC Scenario Pipeline

The following table describes each of the seven pipeline stages in full technical detail. Each stage is implemented as a QSC scenario file located under `edrav2/iprj/edrdata/scenarios/`.

| Stage | Scenario File | Input Queue | Output Queue | Processing Summary |
|---|---|---|---|---|
| 1 | `filter_lle.qsc` | `raw_events` | `filtered_events` | Drops events matching PID whitelist or `baseType` exclusion list; passes all others downstream unchanged |
| 2 | `enrich_lle.qsc` | `filtered_events` | `enriched_events` | Appends process hierarchy (parent chain up to depth 5), image metadata (path, hash, signature), user context, and session information |
| 3 | `match_patterns.qsc` | `enriched_events` | `matched_events` | Evaluates all `patterns` blocks from the active policy file; tags events with matching pattern IDs; drops events that match no pattern if `dropUnmatched` is set |
| 4 | `apply_policy.qsc` | `matched_events` | `policy_events` | Evaluates `events` blocks against tagged pattern IDs and event fields; generates Mid-Level Events (MLE) with severity, tactic, and technique metadata |
| 5 | `get_fls_verdict.qsc` | `policy_events` | `verdict_events` | Queries the FLS (File Lookup Service) for file reputation using SHA-256 hash; annotates events with `flsVerdict` (`clean`, `malicious`, `unknown`) |
| 6 | `check_for_valkyrie.qsc` | `verdict_events` | `valkyrie_events` | Submits files with `flsVerdict: unknown` to the Valkyrie cloud sandbox; awaits or caches verdict; annotates with `valkyrieVerdict` |
| 7 | `output.qsc` | `valkyrie_events` | — | Routes enriched MLE dictionaries to the configured cloud endpoint (Comodo CSCP) and/or local event store; applies event deduplication |

**Stage 1 — filter_lle.qsc**

The filter stage is the pipeline's primary performance optimization. The Windows kernel generates thousands of events per second on a busy endpoint; the vast majority originate from trusted system processes and are irrelevant to threat detection. `filter_lle.qsc` maintains two primary exclusion structures:

- **PID whitelist**: A dynamically maintained set of PIDs corresponding to trusted system processes (e.g., `System`, `smss.exe`, `csrss.exe`). PIDs are added to this set when a `LLE_PROCESS_CREATE` event is observed for a process whose image hash is in the trusted hash list, and removed on `LLE_PROCESS_TERMINATE`.
- **baseType exclusion list**: Certain event types (e.g., high-frequency `LLE_FILE_DATA_READ_FULL` events from antivirus scans) can be globally suppressed for specific process classes.

Events that pass both checks are forwarded unchanged to `filtered_events`. The filter stage runs on a dedicated thread pool to avoid introducing latency on the kernel event capture path.

**Stage 2 — enrich_lle.qsc**

Enrichment adds the contextual data that makes later pattern matching reliable. Raw LLE events contain only the source PID and a handful of event-specific fields. The enrichment stage resolves:

- **Process ancestry**: Walks the live process tree to build a parent chain array (e.g., `explorer.exe → winword.exe → cmd.exe → powershell.exe`), stored as `parentChain: [string]`.
- **Image metadata**: For the source process and any child process referenced in the event, resolves the full image path, computes or retrieves cached SHA-256 and MD5 hashes, and checks the Authenticode signature chain.
- **User context**: Resolves the process token to a human-readable user name and SID, including detection of impersonation scenarios.
- **Session metadata**: Adds `sessionId`, `sessionType` (interactive/remote/service), and `isElevated` boolean.

Enrichment data is cached per PID for the process lifetime to avoid redundant filesystem and cryptographic operations on high-frequency events from the same process.

**Stage 3 — match_patterns.qsc**

Pattern matching is the first detection logic stage. It evaluates the `patterns` section of the active policy file against every enriched event. Each pattern is a named boolean expression over event fields. When a pattern matches, its ID is appended to the event's `matchedPatterns: [string]` array. Events with no matched patterns may be forwarded to Stage 4 (for general logging) or dropped (for performance) based on the `dropUnmatched` policy setting.

**Stage 4 — apply_policy.qsc**

Policy application correlates matched pattern IDs with the `events` section of the policy file to determine whether a detection condition has been met. This stage generates MLE dictionaries with fields including:

- `severity`: `critical` / `high` / `medium` / `low` / `informational`
- `tactic`: MITRE ATT&CK tactic name
- `technique`: MITRE ATT&CK technique ID (e.g., `T1059.001`)
- `ruleName`: Human-readable detection rule name
- `action`: `alert` / `block` / `quarantine` / `terminate`

When `action` is `block` or `terminate`, the policy engine sends a response action message to the kernel driver before forwarding the MLE to Stage 5.

**Stage 5 — get_fls_verdict.qsc**

The FLS (File Lookup Service) stage queries Comodo's cloud file reputation database using the SHA-256 hash of any file involved in the event. This adds a `flsVerdict` field to the MLE:

- `clean`: File is in the trusted global allowlist (over 850 million known-good files).
- `malicious`: File matches a known malware signature.
- `unknown`: File has not been seen before or is not in the database.

FLS queries are batched and cached per hash per session to minimize network overhead. Cache TTL is configurable (default: 1 hour for `clean`, 5 minutes for `unknown`).

**Stage 6 — check_for_valkyrie.qsc**

Files with `flsVerdict: unknown` are candidates for Valkyrie cloud sandbox analysis. This stage submits the file (or its hash, if the file exceeds the configured size limit) to the Valkyrie service. Submissions are rate-limited and deduplicated per hash per day. The stage annotates the MLE with `valkyrieVerdict` and `valkyrieScore` (0–100) when a verdict is available; otherwise, the event proceeds with `valkyrieVerdict: pending`.

**Stage 7 — output.qsc**

The output stage is responsible for durable event delivery. It supports two simultaneous output paths:

- **Cloud endpoint**: Serializes MLE dictionaries to the CSCP (Comodo Security Cloud Protocol) wire format and delivers them to the configured management server over TLS 1.3. Failed deliveries are spooled to a local disk queue and retried with exponential backoff.
- **Local event store**: Appends events to a local SQLite database under `%ProgramData%\OpenArmor\events\`, enabling offline forensic analysis and local SIEM integration via the `edrcon` CLI.

---

### Policy File Structure

The active policy file is a JSON document that defines lists, patterns, and event detection rules. The file is loaded at agent startup and can be updated at runtime. By convention, the source policy is maintained at `edrav2/iprj/edrdata/source_policy.json` and compiled to a binary representation for deployment.

```json
{
  "version": "2.5",
  "metadata": {
    "author": "OpenArmor Security Team",
    "created": "2025-01-15",
    "description": "Production detection policy for Windows endpoints",
    "minAgentVersion": "1.4.0"
  },
  "settings": {
    "dropUnmatched": false,
    "flsEnabled": true,
    "valkyrieEnabled": true,
    "valkyrieMaxFileSizeBytes": 52428800,
    "processTreeDepth": 5,
    "queueMaxDepth": 50000,
    "alertRateLimit": 100
  },
  "lists": {
    "emailClients": ["outlook.exe", "thunderbird.exe", "mailbird.exe", "the bat.exe"],
    "browsers": ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe", "brave.exe"],
    "officeApplications": ["winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "access.exe", "publisher.exe"],
    "scriptInterpreters": ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    "lolBins": ["certutil.exe", "bitsadmin.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe"],
    "infectibleExtensions": [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".pif", ".com"],
    "sensitiveProcesses": ["lsass.exe", "winlogon.exe", "csrss.exe", "services.exe", "svchost.exe"],
    "registryRunKeys": [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "registryWhitelist": [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender"
    ],
    "fileWhitelist": [
      "C:\\Windows\\System32\\",
      "C:\\Windows\\SysWOW64\\",
      "C:\\Program Files\\Windows Defender\\"
    ],
    "trustedSigners": [
      "Microsoft Corporation",
      "Microsoft Windows",
      "Microsoft Windows Publisher"
    ],
    "adminSharePaths": ["\\\\*\\ADMIN$\\", "\\\\*\\C$\\", "\\\\*\\IPC$\\"],
    "credentialDumpTools": ["mimikatz.exe", "procdump.exe", "wce.exe", "pwdump7.exe", "fgdump.exe"]
  },
  "patterns": {
    "encodedPowerShell": {
      "and": [
        { "in": { "field": "processName", "list": "scriptInterpreters" } },
        { "or": [
          { "contains": { "field": "cmdLine", "value": "-EncodedCommand" } },
          { "contains": { "field": "cmdLine", "value": "-enc " } },
          { "contains": { "field": "cmdLine", "value": "-e " } }
        ]}
      ]
    },
    "lsassAccess": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_OPEN" } },
        { "equals": { "field": "targetProcessName", "value": "lsass.exe" } },
        { "not": { "in": { "field": "processName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "powershellEncodedCommand": {
      "pattern": "encodedPowerShell",
      "severity": "high",
      "tactic": "Execution",
      "technique": "T1059.001",
      "ruleName": "PowerShell Encoded Command Execution",
      "action": "alert"
    }
  }
}
```

The top-level keys serve distinct functions:

- **`version`**: Policy schema version. The agent validates compatibility on load; mismatched versions cause the agent to fall back to the last known-good policy.
- **`metadata`**: Informational fields for policy management and audit trail.
- **`settings`**: Runtime tuning parameters that control pipeline behavior (queue depth, rate limiting, feature flags).
- **`lists`**: Named string arrays referenced by patterns using the `in` operator. Lists are centrally managed and can be updated without modifying individual rules.
- **`patterns`**: Named boolean expressions over event fields. Patterns are reusable building blocks referenced by one or more event detection rules.
- **`events`**: Detection rules that map one or more patterns to a specific alert with severity, MITRE ATT&CK classification, and response action.

---

### Pattern Syntax

OpenArmor patterns use a composable, JSON-native expression language. Every expression is a JSON object with a single operator key whose value specifies the operands. Complex expressions are built by nesting operators.

#### `match` — Regular Expression Match

Evaluates a PCRE2 regular expression against a string field. Matching is case-insensitive by default.

```json
{
  "match": {
    "field": "cmdLine",
    "regex": "(?i)(invoke-expression|iex|downloadstring|webclient)",
    "caseSensitive": false
  }
}
```

Use `match` for patterns that require substring extraction, alternation, or quantifiers that cannot be expressed with simpler operators. Note that regex evaluation is more expensive than `equals`, `contains`, or `startsWith`; prefer simpler operators when they suffice.

#### `equals` — Exact String Equality

```json
{
  "equals": {
    "field": "processName",
    "value": "mimikatz.exe"
  }
}
```

Case-insensitive by default. Set `"caseSensitive": true` to enforce exact case matching. Use for process names, registry value names, and other fields with well-defined discrete values.

#### `contains` — Substring Match

```json
{
  "contains": {
    "field": "cmdLine",
    "value": "sekurlsa::logonpasswords"
  }
}
```

Returns true if the field value contains the specified substring at any position. Case-insensitive by default.

#### `startsWith` / `endsWith` — Prefix and Suffix Match

```json
{
  "startsWith": {
    "field": "filePath",
    "value": "C:\\Users\\Public\\"
  }
}
```

```json
{
  "endsWith": {
    "field": "filePath",
    "value": ".locked"
  }
}
```

More efficient than `match` or `contains` for path prefix and file extension checks. Both operators are case-insensitive by default.

#### `in` — List Membership

```json
{
  "in": {
    "field": "processName",
    "list": "browsers"
  }
}
```

Tests whether the field value appears in a named list defined in the `lists` section of the policy file. The `list` key references the list by name. Use `in` instead of repeated `or`/`equals` combinations for maintainability; updating the list automatically updates all patterns that reference it.

For inline lists (not requiring central management), use the `values` key:

```json
{
  "in": {
    "field": "fileExtension",
    "values": [".exe", ".dll", ".bat", ".ps1"]
  }
}
```

#### `not` — Logical Negation

```json
{
  "not": {
    "equals": {
      "field": "processName",
      "value": "svchost.exe"
    }
  }
}
```

Inverts any boolean expression. Use `not` with `in` to implement allowlists:

```json
{
  "not": {
    "in": {
      "field": "processPath",
      "list": "fileWhitelist"
    }
  }
}
```

#### `and` / `or` — Logical Combinators

```json
{
  "and": [
    { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
    { "in": { "field": "parentName", "list": "officeApplications" } },
    { "in": { "field": "processName", "list": "scriptInterpreters" } }
  ]
}
```

```json
{
  "or": [
    { "contains": { "field": "cmdLine", "value": "-EncodedCommand" } },
    { "contains": { "field": "cmdLine", "value": "-WindowStyle Hidden" } },
    { "contains": { "field": "cmdLine", "value": "bypass" } }
  ]
}
```

Both operators accept an array of two or more child expressions. `and` uses short-circuit evaluation (stops at first false). `or` uses short-circuit evaluation (stops at first true). Operands are evaluated left to right.

#### `exists` — Field Presence Check

```json
{
  "exists": {
    "field": "childPid"
  }
}
```

Returns true if the named field is present in the event dictionary and is not null. Use `exists` to differentiate between event subtypes that share a base type but have different optional fields.

#### `gt` / `lt` / `gte` / `lte` — Numeric Comparisons

```json
{
  "gt": {
    "field": "fileSize",
    "value": 0
  }
}
```

```json
{
  "lte": {
    "field": "parentChainDepth",
    "value": 3
  }
}
```

All four operators perform signed 64-bit integer comparison. The `value` operand must be a JSON number. These operators are used for size thresholds, depth limits, count-based detection (e.g., files encrypted in a time window), and port number checks.

**Combining Operators — Full Example**

```json
{
  "and": [
    { "equals": { "field": "baseType", "value": "LLE_NETWORK_CONNECT_OUT" } },
    { "not": { "in": { "field": "processName", "list": "browsers" } } },
    { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
    { "or": [
      { "equals": { "field": "remotePort", "value": 443 } },
      { "equals": { "field": "remotePort", "value": 80 } }
    ]},
    { "gt": { "field": "dataTransferredBytes", "value": 10485760 } }
  ]
}
```

This pattern matches any outbound HTTP/HTTPS connection from a non-browser, non-whitelisted process that transfers more than 10 MB — a potential data exfiltration indicator.

---

### Writing Detection Rules

Detection rules are defined under the `events` key of the policy file. Each rule references one or more patterns (from the `patterns` section) and specifies the alert metadata and response action. The following ten examples cover the most critical detection scenarios relevant to enterprise Windows endpoints.

---

**Example 1: PowerShell Encoded Command Detection**

Detects execution of PowerShell with Base64-encoded command arguments, a technique commonly used to obfuscate malicious scripts.

```json
{
  "patterns": {
    "powershellEncodedCmd": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "or": [
          { "equals": { "field": "processName", "value": "powershell.exe" } },
          { "equals": { "field": "processName", "value": "pwsh.exe" } }
        ]},
        { "or": [
          { "match": { "field": "cmdLine", "regex": "(?i)-e(nc(odedcommand)?)? [A-Za-z0-9+/]{20,}={0,2}" } },
          { "contains": { "field": "cmdLine", "value": "-EncodedCommand" } },
          { "contains": { "field": "cmdLine", "value": "FromBase64String" } }
        ]},
        { "not": { "in": { "field": "parentName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "rule_powershell_encoded": {
      "pattern": "powershellEncodedCmd",
      "severity": "high",
      "tactic": "Execution",
      "technique": "T1059.001",
      "ruleName": "PowerShell Encoded Command Execution",
      "description": "PowerShell launched with Base64-encoded command argument. Commonly used to bypass script block logging and evade signature detection.",
      "action": "alert",
      "responseActions": ["captureProcessMemory", "collectPrefetch"]
    }
  }
}
```

*Explanation*: The pattern targets process creation events for `powershell.exe` or `pwsh.exe`. The `cmdLine` check uses a regex that matches the common `-enc`/`-e`/`-EncodedCommand` abbreviations followed by a Base64 string, as well as direct use of `FromBase64String` in inline scripts. The `not in trustedSigners` clause prevents false positives from signed Microsoft tooling that legitimately uses encoded commands (e.g., some Windows installer components).

---

**Example 2: LSASS Process Access Detection**

Detects when any process opens a handle to `lsass.exe` with memory-read permissions — the first step in credential dumping attacks.

```json
{
  "patterns": {
    "lsassHandleOpen": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_OPEN" } },
        { "equals": { "field": "targetProcessName", "value": "lsass.exe" } },
        { "or": [
          { "equals": { "field": "accessMask", "value": "PROCESS_VM_READ" } },
          { "equals": { "field": "accessMask", "value": "PROCESS_ALL_ACCESS" } },
          { "contains": { "field": "accessMask", "value": "0x10" } }
        ]},
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "not": { "in": { "field": "signerName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "rule_lsass_access": {
      "pattern": "lsassHandleOpen",
      "severity": "critical",
      "tactic": "Credential Access",
      "technique": "T1003.001",
      "ruleName": "LSASS Handle Opened for Memory Read",
      "description": "A non-trusted process has opened a handle to lsass.exe with VM_READ or ALL_ACCESS permissions. This is the primary precursor to credential dumping.",
      "action": "block",
      "responseActions": ["terminateProcess", "quarantineFile", "captureProcessMemory"]
    }
  }
}
```

*Explanation*: The rule targets `LLE_PROCESS_OPEN` events where the target is LSASS and the requested access mask includes read permission. The allowlist checks on `fileWhitelist` and `trustedSigners` permit legitimate security tooling (e.g., Windows Defender, CrowdStrike sensor itself) while blocking untrusted processes. The `action: block` directive instructs the kernel driver to deny the handle open call before the credential read occurs.

---

**Example 3: Suspicious Child Process of Office Application**

Detects when a Microsoft Office application spawns a shell interpreter or living-off-the-land binary — the classic macro execution pattern.

```json
{
  "patterns": {
    "officeSpawnsShell": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "in": { "field": "parentName", "list": "officeApplications" } },
        { "or": [
          { "in": { "field": "processName", "list": "scriptInterpreters" } },
          { "in": { "field": "processName", "list": "lolBins" } },
          { "match": { "field": "processName", "regex": "(?i)(net\\.exe|net1\\.exe|nltest\\.exe|whoami\\.exe|ipconfig\\.exe|systeminfo\\.exe)" } }
        ]}
      ]
    }
  },
  "events": {
    "rule_office_spawns_shell": {
      "pattern": "officeSpawnsShell",
      "severity": "high",
      "tactic": "Execution",
      "technique": "T1559.001",
      "ruleName": "Office Application Spawned Script Interpreter",
      "description": "A Microsoft Office process spawned a shell interpreter or LOLBIN. This pattern is strongly associated with macro-based malware execution.",
      "action": "alert",
      "responseActions": ["collectParentProcess", "collectMacroContent"]
    }
  }
}
```

*Explanation*: The parent-child relationship check (`in officeApplications` → `in scriptInterpreters` or `in lolBins`) is one of the highest-fidelity signals in Windows threat detection. Legitimate Office macros rarely spawn `cmd.exe`, `powershell.exe`, or `wmic.exe`. Additional child processes like `whoami.exe` and `systeminfo.exe` are included because they indicate reconnaissance activity immediately following macro execution.

---

**Example 4: Mass File Encryption (Ransomware Pattern)**

Detects the file enumeration and bulk write pattern characteristic of ransomware using a sliding window event counter.

```json
{
  "patterns": {
    "massFileWriteWithRename": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_FILE_RENAME" } },
        { "or": [
          { "match": { "field": "newFilePath", "regex": "(?i)\\.(locked|encrypted|enc|crypted|crypt|crypto|rnsmwr|wncry|wcry|pay2decrypt|zepto|locky|cerber|sage|globeimposter)$" } },
          { "match": { "field": "newFilePath", "regex": "\\.[a-zA-Z0-9]{4,8}$" } }
        ]},
        { "gt": { "field": "processFileWriteCount60s", "value": 50 } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } }
      ]
    }
  },
  "events": {
    "rule_ransomware_behavior": {
      "pattern": "massFileWriteWithRename",
      "severity": "critical",
      "tactic": "Impact",
      "technique": "T1486",
      "ruleName": "Mass File Encryption — Ransomware Behavior",
      "description": "Process has performed more than 50 file write operations in 60 seconds and is renaming files with suspicious extensions. Ransomware activity suspected.",
      "action": "terminate",
      "responseActions": ["terminateProcess", "quarantineFile", "snapshotFilesystem", "isolateNetwork"]
    }
  }
}
```

*Explanation*: The `processFileWriteCount60s` field is a derived field populated by the enrichment stage that tracks per-process file write event counts in a rolling 60-second window. The threshold of 50 writes combined with the extension rename pattern provides high confidence with acceptable false positive rates. The `action: terminate` with `isolateNetwork` ensures the ransomware process is killed and the host is network-isolated to prevent propagation before security staff are notified.

---

**Example 5: Registry Persistence via Run Key Modification**

Detects when a non-trusted process writes to standard autostart registry locations.

```json
{
  "patterns": {
    "registryRunKeyWrite": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_REGISTRY_VALUE_WRITE" } },
        { "in": { "field": "registryKeyPath", "list": "registryRunKeys" } },
        { "not": { "in": { "field": "registryKeyPath", "list": "registryWhitelist" } } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "not": { "in": { "field": "signerName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "rule_registry_persistence": {
      "pattern": "registryRunKeyWrite",
      "severity": "high",
      "tactic": "Persistence",
      "technique": "T1547.001",
      "ruleName": "Registry Run Key Persistence",
      "description": "An untrusted process has written to a registry autostart location. This is a common persistence mechanism used by malware to survive reboots.",
      "action": "alert",
      "responseActions": ["captureRegistryValue", "collectWritingProcess"]
    }
  }
}
```

*Explanation*: The three allowlist checks (path, registry key, signer) are essential for reducing false positives in enterprise environments, where legitimate software installers frequently write to Run keys. By requiring all three conditions to be absent from their respective allowlists, the rule targets genuinely suspicious writes. The `captureRegistryValue` response action records the written value for forensic analysis.

---

**Example 6: Net.exe Lateral Movement Commands**

Detects enumeration and lateral movement commands using `net.exe` and `net1.exe`.

```json
{
  "patterns": {
    "netExeLateralMovement": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "or": [
          { "equals": { "field": "processName", "value": "net.exe" } },
          { "equals": { "field": "processName", "value": "net1.exe" } }
        ]},
        { "or": [
          { "match": { "field": "cmdLine", "regex": "(?i)net(1)? (user|group|localgroup) .*/add" } },
          { "match": { "field": "cmdLine", "regex": "(?i)net(1)? use \\\\\\\\" } },
          { "match": { "field": "cmdLine", "regex": "(?i)net(1)? view" } },
          { "match": { "field": "cmdLine", "regex": "(?i)net(1)? share" } }
        ]}
      ]
    }
  },
  "events": {
    "rule_net_lateral_movement": {
      "pattern": "netExeLateralMovement",
      "severity": "medium",
      "tactic": "Lateral Movement",
      "technique": "T1021.002",
      "ruleName": "Net.exe Lateral Movement or Reconnaissance",
      "description": "Net.exe was executed with arguments associated with user enumeration, network share mapping, or account creation. Common in lateral movement scenarios.",
      "action": "alert"
    }
  }
}
```

*Explanation*: The regex patterns cover the four most common malicious `net.exe` uses: adding accounts (`/add`), mapping network shares (`net use \\`), enumerating hosts (`net view`), and enumerating shares (`net share`). The medium severity reflects that `net.exe` has legitimate administrative uses; the alert should be correlated with other signals before escalation.

---

**Example 7: WMI Spawning Suspicious Processes**

Detects process creation events where the parent is WMI-related (WmiPrvSE.exe, scrcons.exe) and the child is a known attacker tool.

```json
{
  "patterns": {
    "wmiSpawnsAttackerTool": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "or": [
          { "equals": { "field": "parentName", "value": "wmiprvse.exe" } },
          { "equals": { "field": "parentName", "value": "scrcons.exe" } },
          { "equals": { "field": "parentName", "value": "wmic.exe" } }
        ]},
        { "or": [
          { "in": { "field": "processName", "list": "scriptInterpreters" } },
          { "in": { "field": "processName", "list": "credentialDumpTools" } },
          { "match": { "field": "processName", "regex": "(?i)(whoami|systeminfo|ipconfig|arp|tasklist|net|nltest|certutil|bitsadmin)\\.exe" } }
        ]}
      ]
    }
  },
  "events": {
    "rule_wmi_spawns_tool": {
      "pattern": "wmiSpawnsAttackerTool",
      "severity": "high",
      "tactic": "Execution",
      "technique": "T1047",
      "ruleName": "WMI Process Execution of Suspicious Child",
      "description": "WMI provider process spawned a script interpreter, credential dump tool, or reconnaissance binary. This is a common technique for remote code execution and lateral movement.",
      "action": "alert",
      "responseActions": ["captureProcessTree", "collectWMISubscriptions"]
    }
  }
}
```

*Explanation*: WMI is a frequently abused execution vector because `wmiprvse.exe` (WMI Provider Service) is a trusted system process. Attackers use WMI to spawn processes without creating an obvious parent-child chain from their initial foothold. The rule targets the specific scenario where WMI spawns a tool associated with post-exploitation activity.

---

**Example 8: Credential Dump Tool Execution**

Detects execution of known credential dump tools by name or file hash, including renamed copies detected by hash matching.

```json
{
  "patterns": {
    "credentialDumpExecution": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "or": [
          { "in": { "field": "processName", "list": "credentialDumpTools" } },
          { "in": { "field": "processHash.sha256", "list": "knownMaliciousHashes" } },
          { "and": [
            { "equals": { "field": "processName", "value": "procdump.exe" } },
            { "match": { "field": "cmdLine", "regex": "(?i)(procdump.*lsass|lsass.*-ma)" } }
          ]},
          { "match": { "field": "cmdLine", "regex": "(?i)(sekurlsa|lsadump|kerberos::list|token::elevate|vault::cred)" } }
        ]}
      ]
    }
  },
  "events": {
    "rule_credential_dump": {
      "pattern": "credentialDumpExecution",
      "severity": "critical",
      "tactic": "Credential Access",
      "technique": "T1003",
      "ruleName": "Credential Dumping Tool Executed",
      "description": "A known credential dumping tool was executed, or a process was launched with command-line arguments associated with credential extraction.",
      "action": "block",
      "responseActions": ["terminateProcess", "quarantineFile", "captureMemory", "isolateIfRepeated"]
    }
  }
}
```

*Explanation*: This rule uses a layered approach: name matching catches default filenames, hash matching catches known samples regardless of filename, argument matching catches Sysinternals `procdump` when used against LSASS specifically, and command-line substring matching catches Mimikatz module invocations. The `action: block` with `terminateProcess` ensures the tool is stopped before any credentials are exfiltrated.

---

**Example 9: Macro-Enabled Office Document Spawning Network Process**

Detects when an Office application spawns a process that then establishes a network connection — the complete macro-to-C2 chain.

```json
{
  "patterns": {
    "officeChildNetworkConnect": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_NETWORK_CONNECT_OUT" } },
        { "in": { "field": "grandparentName", "list": "officeApplications" } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "not": { "equals": { "field": "remotePort", "value": 443 } } }
      ]
    },
    "officeChildDownload": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_NETWORK_HTTP_REQUEST" } },
        { "in": { "field": "grandparentName", "list": "officeApplications" } },
        { "match": { "field": "requestUrl", "regex": "(?i)\\.(exe|dll|ps1|bat|vbs|hta)$" } }
      ]
    }
  },
  "events": {
    "rule_office_macro_c2": {
      "pattern": "officeChildNetworkConnect",
      "severity": "critical",
      "tactic": "Command and Control",
      "technique": "T1071.001",
      "ruleName": "Office Macro Descendant Network Connection",
      "description": "A process descended from a Microsoft Office application established an outbound network connection. This is consistent with a malicious macro establishing C2 communication.",
      "action": "alert",
      "responseActions": ["blockConnection", "capturePackets", "collectOfficeDocument"]
    },
    "rule_office_macro_download": {
      "pattern": "officeChildDownload",
      "severity": "critical",
      "tactic": "Command and Control",
      "technique": "T1105",
      "ruleName": "Office Macro Descendant File Download",
      "description": "A process descended from a Microsoft Office application downloaded an executable or script file via HTTP.",
      "action": "block",
      "responseActions": ["blockConnection", "quarantineDownloadedFile", "collectOfficeDocument"]
    }
  }
}
```

*Explanation*: The `grandparentName` field (populated by the enrichment stage's process ancestry walk) allows detection of multi-hop chains like `winword.exe → cmd.exe → powershell.exe → network`. This is more reliable than checking direct parent relationships, which attackers evade by inserting an additional process hop.

---

**Example 10: Unusual Parent-Child Process Relationships**

Detects generic anomalous parent-child relationships using a combination of expected-parent rules and process ancestry depth checks.

```json
{
  "patterns": {
    "unexpectedParentForSystemProcess": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "or": [
          {
            "and": [
              { "equals": { "field": "processName", "value": "svchost.exe" } },
              { "not": { "or": [
                { "equals": { "field": "parentName", "value": "services.exe" } },
                { "equals": { "field": "parentName", "value": "MsMpEng.exe" } }
              ]}}
            ]
          },
          {
            "and": [
              { "equals": { "field": "processName", "value": "lsass.exe" } },
              { "not": { "equals": { "field": "parentName", "value": "wininit.exe" } } }
            ]
          },
          {
            "and": [
              { "equals": { "field": "processName", "value": "spoolsv.exe" } },
              { "not": { "equals": { "field": "parentName", "value": "services.exe" } } }
            ]
          },
          {
            "and": [
              { "in": { "field": "processName", "list": "scriptInterpreters" } },
              { "in": { "field": "parentName", "list": "sensitiveProcesses" } }
            ]
          }
        ]}
      ]
    }
  },
  "events": {
    "rule_unusual_parent_child": {
      "pattern": "unexpectedParentForSystemProcess",
      "severity": "high",
      "tactic": "Defense Evasion",
      "technique": "T1036.003",
      "ruleName": "Anomalous Parent-Child Process Relationship",
      "description": "A system process was spawned by an unexpected parent, or a script interpreter was spawned by a sensitive system process. This may indicate process masquerading or code injection.",
      "action": "alert",
      "responseActions": ["captureProcessTree", "captureProcessMemory"]
    }
  }
}
```

*Explanation*: Windows has well-defined parent-child relationships for core system processes. `svchost.exe` is always spawned by `services.exe` under normal conditions; `lsass.exe` is always spawned by `wininit.exe`. Any deviation is a strong indicator of process injection, masquerading, or a rootkit. The rule enumerates these invariants and generates high-severity alerts on any violation.

---

### Testing Policies

OpenArmor provides the `edrcon` command-line tool for policy compilation, validation, and offline testing. Policy testing should be integrated into CI/CD pipelines to prevent regressions when modifying detection rules.

**Compiling and Validating a Policy File**

```cmd
REM Compile the source policy JSON and validate syntax
edrcon compile --policy edrav2\iprj\edrdata\source_policy.json

REM Example output on success:
REM [INFO] Loading policy: source_policy.json
REM [INFO] Policy version: 2.5
REM [INFO] Lists defined: 14
REM [INFO] Patterns defined: 47
REM [INFO] Events defined: 63
REM [INFO] Compilation successful — output: source_policy.bin
REM [INFO] Estimated per-event evaluation time: 0.8 µs (p99)

REM Compile and output to a specific path
edrcon compile --policy source_policy.json --output dist\policy.bin

REM Validate only (no output file)
edrcon compile --policy source_policy.json --validate-only
```

**Testing Against Sample Events**

```cmd
REM Run policy evaluation against a recorded event stream
edrcon compile --policy policy.json --test-events test\events\mimikatz_chain.json

REM Example output:
REM [TEST] Processing 47 events from test file
REM [TEST] Event 12: MATCH rule_lsass_access (severity=critical, action=block)
REM [TEST] Event 23: MATCH rule_credential_dump (severity=critical, action=block)
REM [TEST] Event 35: NO MATCH
REM [TEST] Summary: 2 rules fired, 0 expected misses, 0 false positives vs baseline

REM Test with expected results baseline
edrcon compile --policy policy.json \
  --test-events test\events\mimikatz_chain.json \
  --expected-results test\baselines\mimikatz_expected.json

REM Test all scenarios in a directory
edrcon compile --policy policy.json --test-events-dir test\events\
```

**Debug Mode — Tracing Policy Evaluation**

```cmd
REM Enable full policy evaluation trace (verbose)
edrcon debug --policy-trace --policy policy.json --event event.json

REM Example output:
REM [TRACE] Evaluating event: baseType=LLE_PROCESS_CREATE pid=4892
REM [TRACE]   Pattern: encodedPowerShell
REM [TRACE]     and[0]: equals(baseType, LLE_PROCESS_CREATE) -> TRUE
REM [TRACE]     and[1]: in(processName, scriptInterpreters) -> TRUE (matched: powershell.exe)
REM [TRACE]     and[2]: or[0]: contains(cmdLine, -EncodedCommand) -> TRUE
REM [TRACE]   Pattern result: encodedPowerShell -> MATCH
REM [TRACE]   Rule: rule_powershell_encoded
REM [TRACE]     pattern: encodedPowerShell -> MATCH
REM [TRACE]     -> ALERT generated (severity=high, technique=T1059.001)

REM Attach debug tracer to live agent (requires elevated privileges)
edrcon debug --policy-trace --live --filter "severity=critical"

REM Dump the compiled pattern decision tree
edrcon debug --dump-pattern-tree --policy policy.bin
```

**Generating Test Event Files**

```cmd
REM Record live events to a test file for offline replay
edrcon record --output test\events\session_capture.json --duration 60

REM Filter recorded events by type
edrcon record --output test\events\process_events.json \
  --filter "baseType=LLE_PROCESS_CREATE,LLE_PROCESS_OPEN" \
  --duration 300

REM Synthetically generate test events
edrcon generate-event --type LLE_PROCESS_CREATE \
  --processName powershell.exe \
  --cmdLine "powershell.exe -EncodedCommand JABhAD0AMQAy" \
  --parentName winword.exe \
  --output test\events\synthetic_macro_spawn.json
```

---

### Tuning False Positives

Managing false positives is an ongoing operational process. OpenArmor provides multiple layers of suppression to address common false positive scenarios without disabling entire detection rules.

**Adding Process Path Exclusions**

When a specific legitimate application triggers a rule, add its installation path to the relevant list:

```json
{
  "lists": {
    "fileWhitelist": [
      "C:\\Windows\\System32\\",
      "C:\\Windows\\SysWOW64\\",
      "C:\\Program Files\\Windows Defender\\",
      "C:\\Program Files\\CorporateApp\\bin\\",
      "C:\\Program Files (x86)\\LegacyApp\\"
    ]
  }
}
```

For temporary or user-specific paths, prefer per-rule exclusion conditions:

```json
{
  "patterns": {
    "powershellEncodedCmd": {
      "and": [
        { "... existing conditions ..." : {} },
        { "not": { "startsWith": { "field": "processPath", "value": "C:\\Program Files\\AutomationTool\\" } } },
        { "not": { "equals": { "field": "parentName", "value": "jenkins.exe" } } }
      ]
    }
  }
}
```

**Adding Trusted Signer Exclusions**

For software from known vendors that legitimately triggers detection logic:

```json
{
  "lists": {
    "trustedSigners": [
      "Microsoft Corporation",
      "Microsoft Windows Publisher",
      "Cisco Systems, Inc.",
      "Palo Alto Networks",
      "CorporateSoftware Ltd."
    ]
  }
}
```

**Adjusting Count Thresholds**

For rules based on event frequency (e.g., the ransomware rule), adjust the threshold to match legitimate application behavior:

```json
{
  "gt": { "field": "processFileWriteCount60s", "value": 200 }
}
```

Document every threshold change with a justification comment (in the policy file `metadata.exclusions` array):

```json
{
  "metadata": {
    "exclusions": [
      {
        "rule": "rule_ransomware_behavior",
        "change": "Raised file write threshold from 50 to 200",
        "reason": "Backup agent (Veeam) triggers at threshold 50 during scheduled backups",
        "approvedBy": "security-team@corp.example.com",
        "approvalDate": "2025-03-10",
        "reviewDate": "2025-06-10"
      }
    ]
  }
}
```

**Per-User and Per-Machine Exclusions**

For exclusions that apply only to specific users (e.g., developers running security research tools):

```json
{
  "and": [
    { "... existing pattern ..." : {} },
    { "not": {
      "and": [
        { "in": { "field": "userName", "values": ["DOMAIN\\researcher1", "DOMAIN\\pentest"] } },
        { "in": { "field": "machineName", "values": ["SECRESEARCH01", "PENTEST-LAB"] } }
      ]
    }}
  ]
}
```

**Graduated Alert Severity**

Instead of generating `critical` alerts for noisy rules during initial deployment, reduce the severity and review before escalating:

```json
{
  "events": {
    "rule_net_lateral_movement": {
      "severity": "low",
      "action": "alert"
    }
  }
}
```

After a two-week observation period, review the alert volume, identify legitimate callers, add appropriate exclusions, and raise the severity to `medium` or `high`.

---

### Policy Versioning and Deployment

OpenArmor supports live policy updates without agent restart, enabling rapid response to emerging threats and policy corrections.

**Live Policy Update via CloudConfigurationIsChanged**

The management server pushes policy updates by sending a `CloudConfigurationIsChanged` message to all enrolled agents. The agent validates the new policy schema and version before applying it:

```
Management Server                         OpenArmor Agent
      |                                         |
      |-- CloudConfigurationIsChanged --------> |
      |   { policyUrl, policyHash, version }    |
      |                                         |-- Download policy from policyUrl
      |                                         |-- Verify SHA-256 matches policyHash
      |                                         |-- Validate schema and version
      |                                         |-- If valid: swap active policy (atomic)
      |                                         |-- If invalid: retain current policy
      |                                         |-- Send ConfigurationUpdateAck
      |<-- ConfigurationUpdateAck ------------- |
      |   { status, appliedVersion, agentId }   |
```

The policy swap is atomic: the new compiled binary representation is written to a temporary file, validated, and then swapped in a single file rename operation. Events in flight when the swap occurs are evaluated against the old policy until they complete; new events from the next queue read use the new policy.

**Policy Rollback**

The agent maintains the last three applied policy versions in `%ProgramData%\OpenArmor\policy\`:

```
policy_current.bin    — Active policy
policy_prev_1.bin     — Previous policy
policy_prev_2.bin     — Policy before that
policy_prev_3.bin     — Oldest retained policy
```

To roll back from the management server:

```cmd
REM Roll back on the management server side by redeploying a previous version
edrcon policy rollback --target all --version 2.4 --reason "FP spike in rule_xxx"

REM Roll back on a specific agent (emergency, local CLI)
edrcon policy rollback --local --steps 1
```

**Staged Deployment**

Policy updates should follow a staged rollout to limit blast radius from newly introduced false positives:

1. **Stage 1 — Lab validation**: Deploy to isolated test machines and run `edrcon compile --test-events` against the full scenario library. Require zero new false positives vs. the current baseline.
2. **Stage 2 — Canary deployment (1–5%)**: Deploy to a small percentage of production endpoints, typically IT staff machines with high activity. Monitor alert volume and FP rate for 24–48 hours.
3. **Stage 3 — Ring expansion (25%)**: Expand to a broader ring. Continue monitoring.
4. **Stage 4 — General availability (100%)**: Full deployment after the canary period clears.

The management server policy deployment API supports percentage-based targeting:

```json
{
  "policyDeployment": {
    "policyVersion": "2.5",
    "rolloutPercentage": 5,
    "targetGroups": ["canary"],
    "rolloutSchedule": "2025-04-01T09:00:00Z",
    "autoRollbackOnFPSpike": true,
    "fpSpikeThreshold": 2.0,
    "fpSpikeWindowMinutes": 60
  }
}
```

---

## Event Types Reference

The OpenArmor kernel driver captures events from multiple Windows subsystems through a combination of kernel callbacks, minifilter drivers, and NDIS filtering. All events are normalized to the Variant dictionary schema before entering the QSC pipeline.

### Low-Level Events (LLE)

Low-Level Events represent atomic, kernel-observed system activities. Each LLE carries a `baseType` discriminator and a set of type-specific fields layered on top of the common event schema.

---

#### Process Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_PROCESS_CREATE` | Process Creation | A new process was spawned on the system | `PsSetCreateProcessNotifyRoutineEx` callback fired (process created) |
| `LLE_PROCESS_TERMINATE` | Process Termination | A process exited normally or was killed | `PsSetCreateProcessNotifyRoutineEx` callback fired (process exiting) |
| `LLE_PROCESS_OPEN` | Process Handle Open | A process opened a handle to another process | `ObRegisterCallbacks` pre-operation callback on `PsProcessType` |
| `LLE_PROCESS_MEMORY_READ` | Cross-Process Memory Read | A process read memory from another process's address space | Inline hook on `NtReadVirtualMemory` with cross-process detection |
| `LLE_PROCESS_MEMORY_WRITE` | Cross-Process Memory Write | A process wrote to another process's address space | Inline hook on `NtWriteVirtualMemory` with cross-process detection |
| `LLE_PROCESS_IMPERSONATION` | Thread Impersonation | A thread assumed the security context of another user | `PsSetCreateThreadNotifyRoutine` + token impersonation detection |

**LLE_PROCESS_CREATE** — Key Fields:
- `childPid`: uint64 — PID of the newly created process
- `childPath`: string — Full image path of the child process
- `childCmdLine`: string — Complete command line passed to the child
- `childHash`: dict — `{sha256, md5, xxhash}` of the child image
- `childSignature`: dict — `{publisher, valid, trusted}` Authenticode result
- `childParentPid`: uint64 — Confirmed parent PID (from kernel, not user-land)
- `isProtected`: bool — Whether the child is a Protected Process Light (PPL)
- `integrityLevel`: string — `System` / `High` / `Medium` / `Low` / `Untrusted`

**LLE_PROCESS_OPEN** — Key Fields:
- `targetPid`: uint64 — PID of the process whose handle was opened
- `targetProcessName`: string — Image name of the target process
- `targetProcessPath`: string — Full image path of the target process
- `accessMask`: string — Requested access rights (e.g., `PROCESS_VM_READ`, `PROCESS_ALL_ACCESS`)
- `accessMaskRaw`: uint32 — Raw numeric access mask value
- `grantedAccess`: uint32 — Actually granted access after policy application
- `handleDuplicated`: bool — Whether the handle was created via `DuplicateHandle`

**LLE_PROCESS_MEMORY_READ / LLE_PROCESS_MEMORY_WRITE** — Key Fields:
- `targetPid`: uint64 — PID of the process whose memory was accessed
- `targetProcessName`: string — Image name of the target
- `baseAddress`: uint64 — Base virtual address of the memory operation
- `regionSize`: uint64 — Number of bytes read or written
- `bytesTransferred`: uint64 — Actual bytes transferred
- `targetRegionProtect`: string — Memory protection flags on the target region (e.g., `PAGE_EXECUTE_READ`)

---

#### File Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_FILE_CREATE` | File Creation | A new file was created | Minifilter `IRP_MJ_CREATE` with `FILE_CREATED` disposition |
| `LLE_FILE_OPEN` | File Open | An existing file was opened | Minifilter `IRP_MJ_CREATE` with `FILE_OPENED` disposition |
| `LLE_FILE_WRITE` | File Write | Data was written to a file | Minifilter `IRP_MJ_WRITE` post-operation callback |
| `LLE_FILE_RENAME` | File or Directory Rename | A file or directory was renamed or moved | Minifilter `IRP_MJ_SET_INFORMATION` with `FileRenameInformation` |
| `LLE_FILE_DELETE` | File Deletion | A file was deleted | Minifilter `IRP_MJ_SET_INFORMATION` with `FileDispositionInformation` |
| `LLE_FILE_DATA_READ_FULL` | Full File Content Read | Complete file content was read (large read operations) | Minifilter `IRP_MJ_READ` with accumulated read size >= file size |

**File Event Common Fields:**
- `filePath`: string — NT path of the target file (e.g., `\Device\HarddiskVolume3\Users\user\Desktop\evil.exe`)
- `filePathWin32`: string — Win32 path (e.g., `C:\Users\user\Desktop\evil.exe`)
- `fileSize`: uint64 — File size in bytes at time of event
- `fileHash`: dict — `{sha256, md5}` (computed asynchronously; may be absent for very large files)
- `fileSignature`: dict — `{publisher, valid, trusted}` (Authenticode result)
- `flsVerdict`: string — `clean` / `malicious` / `unknown` (populated by Stage 5)
- `fileExtension`: string — Lowercase file extension (e.g., `.exe`, `.ps1`)
- `isAlternateDataStream`: bool — True if the operation targets an NTFS alternate data stream
- `adsStreamName`: string — ADS stream name (if `isAlternateDataStream` is true)

**LLE_FILE_RENAME** Additional Fields:**
- `oldFilePath`: string — Original file path before rename
- `newFilePath`: string — Target file path after rename
- `isDirectoryRename`: bool — True if renaming a directory

---

#### Registry Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_REGISTRY_KEY_CREATE` | Registry Key Creation | A new registry key was created | `CmRegisterCallback` pre/post on `RegNtPreCreateKey` |
| `LLE_REGISTRY_KEY_DELETE` | Registry Key Deletion | A registry key was deleted | `CmRegisterCallback` on `RegNtPreDeleteKey` |
| `LLE_REGISTRY_KEY_RENAME` | Registry Key Rename | A registry key was renamed | `CmRegisterCallback` on `RegNtPreRenameKey` |
| `LLE_REGISTRY_VALUE_WRITE` | Registry Value Write | A registry value was created or modified | `CmRegisterCallback` on `RegNtPreSetValueKey` |
| `LLE_REGISTRY_VALUE_DELETE` | Registry Value Deletion | A registry value was deleted | `CmRegisterCallback` on `RegNtPreDeleteValueKey` |
| `LLE_REGISTRY_VALUE_READ` | Registry Value Read | A registry value was read | `CmRegisterCallback` on `RegNtPreQueryValueKey` |

**Registry Event Common Fields:**
- `registryKeyPath`: string — Full registry key path (e.g., `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
- `registryHive`: string — Hive name (`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`)
- `registryValueName`: string — Value name (for value-level events)
- `registryValueType`: string — Value data type (`REG_SZ`, `REG_DWORD`, `REG_BINARY`, etc.)
- `registryValueData`: string — Value data as a string representation (for non-binary types)
- `registryValueDataRaw`: bytes — Raw value data (for binary types, base64-encoded)
- `registryValueSize`: uint32 — Value data size in bytes

---

#### Network Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_NETWORK_CONNECT_OUT` | Outbound Connection | A process initiated an outbound TCP/UDP connection | WFP callout on `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` |
| `LLE_NETWORK_CONNECT_IN` | Inbound Connection | An inbound TCP connection was accepted | WFP callout on `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` |
| `LLE_NETWORK_LISTEN` | Port Opened for Listening | A process bound and started listening on a port | WFP callout on `FWPM_LAYER_ALE_AUTH_LISTEN_V4/V6` |
| `LLE_NETWORK_CLOSE` | Connection Closed | A TCP/UDP connection was terminated | WFP callout on `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6` (flow delete) |
| `LLE_NETWORK_DNS_REQUEST` | DNS Query | A DNS query was sent | WFP + DNS protocol parser or ETW DNS client provider |
| `LLE_NETWORK_HTTP_REQUEST` | HTTP Session | An HTTP/HTTPS request was made | WFP + HTTP stream inspection or WinHTTP/WinInet hooks |
| `LLE_NETWORK_FTP_REQUEST` | FTP Session | An FTP session was initiated | WFP + FTP protocol parser |

**Network Event Common Fields:**
- `localAddr`: string — Local IP address and port (`192.168.1.100:52341`)
- `localIp`: string — Local IP address only
- `localPort`: uint16 — Local port number
- `remoteAddr`: string — Remote IP address and port (`93.184.216.34:443`)
- `remoteIp`: string — Remote IP address only
- `remotePort`: uint16 — Remote port number
- `protocol`: string — Transport protocol (`tcp` / `udp` / `icmp`)
- `appProtocol`: string — Application protocol (`http` / `https` / `ftp` / `dns` / `smb` / `rdp` / `other`)
- `direction`: string — `in` / `out`
- `connectionState`: string — `established` / `closed` / `reset` / `timeout`
- `bytesTransferred`: uint64 — Total bytes transferred in both directions
- `dnsQuery`: string — DNS domain queried (`LLE_NETWORK_DNS_REQUEST` only)
- `dnsResponse`: string — Resolved IP address(es) (`LLE_NETWORK_DNS_REQUEST` only)
- `dnsRecordType`: string — DNS record type (`A`, `AAAA`, `MX`, `TXT`, `CNAME`)
- `requestUrl`: string — Full request URL (`LLE_NETWORK_HTTP_REQUEST` only)
- `requestMethod`: string — HTTP method (`GET`, `POST`, `PUT`, etc.)
- `responseCode`: uint16 — HTTP response code
- `userAgent`: string — HTTP User-Agent header value
- `sni`: string — TLS SNI hostname (for HTTPS, if available)
- `tlsVersion`: string — TLS protocol version (`TLS 1.2`, `TLS 1.3`)

---

#### Input and UI Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_INPUT_KEYBOARD_STATE` | Keyboard State Read | A process read keyboard state via `GetKeyState` or `GetAsyncKeyState` | Inline hook on `NtUserGetAsyncKeyState`, `NtUserGetKeyState` |
| `LLE_INPUT_KEYBOARD_HOOK` | Global Keyboard Hook | A process installed a global keyboard hook via `SetWindowsHookEx` | Inline hook on `NtUserSetWindowsHookEx` with `WH_KEYBOARD`/`WH_KEYBOARD_LL` |
| `LLE_INPUT_MOUSE_HOOK` | Global Mouse Hook | A process installed a global mouse hook | Inline hook on `NtUserSetWindowsHookEx` with `WH_MOUSE`/`WH_MOUSE_LL` |
| `LLE_INPUT_BLOCK` | Input Blocked | A process blocked user input via `BlockInput` API | Inline hook on `NtUserBlockInput` |
| `LLE_CLIPBOARD_GET` | Clipboard Data Read | A process read data from the clipboard | Inline hook on `NtUserGetClipboardData` |
| `LLE_CLIPBOARD_WATCH` | Clipboard Monitoring Started | A process installed a clipboard change listener | Inline hook on `NtUserAddClipboardFormatListener` / `SetClipboardViewer` |
| `LLE_SCREEN_CAPTURE` | Screen Captured | A process captured screen content | Inline hook on `NtGdiBitBlt`, `NtUserPrintWindow`, `CopyWindowBitmap` |
| `LLE_AUDIO_CAPTURE` | Audio Device Opened | A process opened an audio capture device | ETW Microsoft-Windows-Audio provider + hook on `waveInOpen` |
| `LLE_WINDOW_HOOK` | Window Hook Installed | A process called `SetWindowsHookEx` with any hook type | Inline hook on `NtUserSetWindowsHookEx` |

**Input/UI Event Fields:**
- `hookType`: string — Hook type identifier (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`, `WH_CBT`, etc.)
- `hookScope`: string — `global` / `thread-local`
- `hookModulePath`: string — Path to the DLL containing the hook procedure (for out-of-process hooks)
- `captureWidth`: uint32 — Screen capture width in pixels (`LLE_SCREEN_CAPTURE` only)
- `captureHeight`: uint32 — Screen capture height in pixels (`LLE_SCREEN_CAPTURE` only)
- `clipboardFormat`: string — Clipboard data format (`CF_TEXT`, `CF_UNICODETEXT`, `CF_BITMAP`, etc.)
- `clipboardDataSize`: uint64 — Size of clipboard data in bytes
- `audioDeviceName`: string — Friendly name of the audio capture device
- `audioDeviceId`: string — Windows audio device GUID

---

#### System Events

| Event Code | Event Name | Description | Trigger Condition |
|---|---|---|---|
| `LLE_SERVICE_CREATE` | Windows Service Created | A new Windows service was registered with the SCM | ETW + SCM registry monitoring on `HKLM\SYSTEM\CurrentControlSet\Services` |
| `LLE_SERVICE_MODIFIED` | Service Configuration Changed | An existing service's configuration was modified | ETW + `ChangeServiceConfig` API hook |
| `LLE_DRIVER_LOAD` | Kernel Driver Loaded | A kernel driver image was loaded into kernel space | `PsSetLoadImageNotifyRoutine` callback with `MmIsAddressValid` + kernel space check |
| `LLE_DRIVER_UNLOAD` | Kernel Driver Unloaded | A kernel driver was unloaded | `PsSetLoadImageNotifyRoutine` callback (unload path) |

**System Event Fields:**
- `serviceName`: string — SCM service name
- `serviceDisplayName`: string — Human-readable service display name
- `serviceBinaryPath`: string — Service binary path (from `ImagePath` registry value)
- `serviceType`: string — `kernel-driver` / `file-system-driver` / `win32-own-process` / `win32-share-process` / `interactive-process`
- `serviceStartType`: string — `boot` / `system` / `automatic` / `manual` / `disabled`
- `serviceAccount`: string — Account under which the service runs
- `driverImagePath`: string — Full path of the loaded driver image
- `driverHash`: dict — `{sha256, md5}` of the driver image
- `driverSignature`: dict — `{publisher, valid, trusted}` — critically important for drivers; unsigned drivers are a major red flag
- `driverLoadAddress`: uint64 — Kernel virtual address where the driver was loaded
- `isWhqlSigned`: bool — Whether the driver has WHQL certification

---

### Event Field Reference

**Common Fields — All LLE Events**

```
baseType        : uint64  — Numeric LLE event code (maps to event type enum)
timestamp       : uint64  — Event capture time as Unix epoch microseconds
pid             : uint64  — Source process ID
tid             : uint64  — Source thread ID
sessionId       : uint32  — Windows logon session ID
userName        : string  — Human-readable account name (DOMAIN\user format)
userSid         : string  — User SID in SDDL format (e.g., S-1-5-21-...)
isElevated      : bool    — True if the process token has elevated privileges
integrityLevel  : string  — Mandatory integrity level (System/High/Medium/Low/Untrusted)
processName     : string  — Process image file name (e.g., powershell.exe)
processPath     : string  — Full Win32 process image path
processHash     : dict    — {sha256: string, md5: string, xxhash: string}
signerName      : string  — Authenticode publisher name (or empty if unsigned)
signatureValid  : bool    — True if the Authenticode signature is valid
signatureTrusted: bool    — True if the signer chain roots to a trusted CA
parentPid       : uint64  — Parent process ID at time of event
parentName      : string  — Parent process image name
parentPath      : string  — Full parent process image path
grandparentName : string  — Grandparent process image name (enrichment, depth 2)
parentChain     : [string]— Ordered list of ancestor names up to depth 5
cmdLine         : string  — Full command line of the source process
machineName     : string  — NetBIOS machine name
machineDomain   : string  — Active Directory domain (or WORKGROUP)
machineId       : string  — Unique machine identifier (hardware hash)
agentVersion    : string  — OpenArmor agent version that captured the event
policyVersion   : string  — Policy version active at capture time
matchedPatterns : [string]— Pattern IDs matched in Stage 3 (added by pipeline)
```

**Process-Specific Fields (LLE_PROCESS_CREATE)**

```
childPid        : uint64  — PID of the created child process
childPath       : string  — Full image path of the child process
childCmdLine    : string  — Command line passed to the child
childHash       : dict    — {sha256, md5, xxhash}
childSignature  : dict    — {publisher, valid, trusted}
childIntegrity  : string  — Child process integrity level
isProtectedPPL  : bool    — Child is a Protected Process Light
injectedCode    : bool    — Early injection detected before main thread runs
```

**File-Specific Fields**

```
filePath        : string  — NT device path of the target file
filePathWin32   : string  — Win32 path of the target file
fileSize        : uint64  — File size in bytes
fileHash        : dict    — {sha256: string, md5: string}
fileSignature   : dict    — {publisher, valid, trusted}
flsVerdict      : string  — clean / malicious / unknown (FLS result)
valkyrieVerdict : string  — clean / malicious / unknown / pending (Valkyrie result)
valkyrieScore   : uint8   — 0-100 Valkyrie maliciousness score
fileExtension   : string  — Lowercase extension (e.g., .exe, .ps1)
isADS           : bool    — True if operating on an NTFS alternate data stream
adsStreamName   : string  — ADS stream name
volumeGuid      : string  — Volume GUID
oldFilePath     : string  — Pre-rename path (LLE_FILE_RENAME only)
newFilePath     : string  — Post-rename path (LLE_FILE_RENAME only)
```

**Network-Specific Fields**

```
localAddr       : string  — Local IP:port (e.g., 192.168.1.5:53412)
localIp         : string  — Local IP address
localPort       : uint16  — Local port number
remoteAddr      : string  — Remote IP:port
remoteIp        : string  — Remote IP address
remotePort      : uint16  — Remote port number
protocol        : string  — tcp / udp / icmp / raw
appProtocol     : string  — http / https / ftp / dns / smb / rdp / other
direction       : string  — in / out
bytesTransferred: uint64  — Total bytes in both directions
dnsQuery        : string  — DNS query domain (LLE_NETWORK_DNS_REQUEST only)
dnsResponse     : string  — Resolved IP(s) (LLE_NETWORK_DNS_REQUEST only)
dnsRecordType   : string  — A / AAAA / MX / TXT / CNAME / NS / SOA
requestUrl      : string  — Full URL (LLE_NETWORK_HTTP_REQUEST only)
requestMethod   : string  — HTTP method
responseCode    : uint16  — HTTP response code
userAgent       : string  — HTTP User-Agent header
sni             : string  — TLS Server Name Indication
tlsVersion      : string  — TLS protocol version
```

---

### Mid-Level Events (MLE)

Mid-Level Events are generated by Stage 4 (`apply_policy.qsc`) when detection conditions are met. Unlike LLEs which represent atomic kernel observations, MLEs represent correlated, analyst-ready security findings. Every MLE includes all fields from its constituent LLEs plus the following detection-specific fields:

```
mleType         : string  — MLE event type identifier
severity        : string  — critical / high / medium / low / informational
tactic          : string  — MITRE ATT&CK tactic name
technique       : string  — MITRE ATT&CK technique ID (e.g., T1059.001)
ruleName        : string  — Human-readable detection rule name
ruleVersion     : string  — Policy version that triggered the detection
description     : string  — Human-readable description of the detection
action          : string  — Action taken: alert / block / terminate / quarantine
actionResult    : string  — Outcome of the response action
correlatedLLEs  : [dict]  — Array of contributing LLE events
indicatorScore  : uint8   — Composite threat score (0-100)
falsePositiveScore: uint8 — Estimated FP probability (0-100, from history)
alertId         : string  — UUID for this specific alert instance
caseId          : string  — Incident management case ID (if assigned)
```

**MLE_SUSPICIOUS_PROCESS_CHAIN**

Generated when Stage 4 identifies an anomalous parent-child relationship or a process ancestry chain that matches a known attack pattern. Fields include the full `parentChain` array and `chainAnomalyReason` string describing which invariant was violated.

**MLE_CREDENTIAL_ACCESS**

Generated when LSASS-targeting events (process open, memory read, or known credential tool execution) are correlated within a 30-second sliding window. Fields include `targetProcess` (`lsass.exe`), `accessMask`, `credentialDumpToolDetected` (bool), and `credentialDataExtracted` (bool, if memory read post LSASS handle was observed).

**MLE_LATERAL_MOVEMENT**

Generated when a combination of network (SMB/WMI/RDP connections) and process execution events are correlated with remote host targets. Fields include `destinationHost`, `lateralMovementVector` (`smb` / `wmi` / `rdp` / `winrm` / `dcom`), and `adminShareAccessed` (bool).

**MLE_PERSISTENCE_ATTEMPT**

Generated when one or more persistence mechanisms are observed: registry autostart writes, service creation, scheduled task registration, startup folder writes, or WMI subscription creation. Fields include `persistenceMethod` (array), `persistenceLocations` (array of paths/keys), and `survivesReboot` (bool estimate).

**MLE_RANSOMWARE_BEHAVIOR**

Generated when mass file write + rename events exceed the configured threshold within the detection window. Fields include `filesAffectedCount`, `fileExtensionsObserved` (array), `estimatedEncryptionRateBytesPerSecond`, and `ransowareFamily` (if identifiable from extension or known hash).

**MLE_DATA_EXFILTRATION**

Generated when a process with access to sensitive files initiates large outbound transfers. Fields include `destinationIp`, `destinationPort`, `dataVolumeBytes`, `transferDurationSeconds`, `sensitivePathsAccessed` (array), and `protocol`.

---

## MITRE ATT&CK Coverage

<picture>
  <source srcset="assets/MITRE_ATT&CK_grid_heatmap_202605010255.avif" type="image/avif">
  <img src="assets/MITRE_ATT&CK_grid_heatmap_202605010255.avif" alt="MITRE ATT&CK Coverage" width="100%">
</picture>

### Coverage Matrix

OpenArmor's detection coverage maps to 13 of the 14 MITRE ATT&CK for Enterprise tactics. The following table provides a complete coverage overview, including coverage level, monitored technique IDs, the detection mechanism in OpenArmor, and a representative example rule for each tactic.

| Tactic | Coverage Level | Key Monitored Techniques | Detection Mechanism | Example Rule |
|---|---|---|---|---|
| Reconnaissance | Partial | T1592, T1590, T1589 | Process + API correlation for local recon; limited pre-compromise visibility | `rule_system_info_discovery` — `systeminfo.exe`, `whoami.exe`, `ipconfig.exe` execution |
| Resource Development | None | — | Pre-compromise activity; no endpoint visibility | N/A |
| Initial Access | Partial | T1566.001, T1189, T1195 | File download monitoring, macro execution chain, Office spawning shell | `rule_office_macro_c2` — Office spawning shell + network |
| Execution | High | T1059.001–T1059.007, T1047, T1053, T1203 | Process creation monitoring, command-line analysis, WMI/scheduled task correlation | `rule_powershell_encoded`, `rule_wmi_spawns_tool` |
| Persistence | High | T1547.001, T1543.003, T1053.005, T1546.003, T1574 | Registry autostart monitoring, service creation, scheduled task, WMI subscription, DLL search order | `rule_registry_persistence`, `rule_service_creation` |
| Privilege Escalation | High | T1548.002, T1134, T1055, T1068 | Token impersonation hooks, process injection detection, UAC bypass patterns | `rule_process_impersonation`, `rule_process_injection` |
| Defense Evasion | High | T1036, T1055, T1562, T1112, T1070, T1027 | Process name/path anomalies, injection, EDR-targeting processes, registry modification, log clearing | `rule_unusual_parent_child`, `rule_edr_process_access` |
| Credential Access | High | T1003.001, T1003.002, T1056, T1555, T1558 | LSASS handle monitoring, credential dump tool detection, keylogger hook detection | `rule_lsass_access`, `rule_credential_dump` |
| Discovery | Medium | T1082, T1083, T1018, T1033, T1049, T1069 | Process + command-line monitoring for recon tools, network enumeration | `rule_net_lateral_movement`, `rule_system_info_discovery` |
| Lateral Movement | High | T1021.001–T1021.006, T1047, T1175 | Network (SMB/RDP/WMI) + process correlation, remote process creation detection | `rule_net_lateral_movement`, `rule_wmi_spawns_tool` |
| Collection | High | T1056, T1113, T1115, T1123, T1005 | Keylogger hooks, screen capture hooks, clipboard monitoring, audio capture hooks | `rule_keyboard_hook`, `rule_screen_capture`, `rule_clipboard_monitor` |
| Command and Control | High | T1071, T1095, T1105, T1132, T1571 | Network connection analysis, HTTP/DNS C2 pattern detection, file download monitoring | `rule_office_macro_c2`, `rule_suspicious_beacon` |
| Exfiltration | Medium | T1041, T1048, T1071, T1030 | Large outbound transfer detection, process + network correlation | `rule_data_exfiltration` |
| Impact | High | T1486, T1490, T1489, T1498, T1491 | Mass file rename/write (ransomware), VSS deletion, service termination, disk wipe | `rule_ransomware_behavior`, `rule_vss_deletion` |

**Coverage Level Definitions:**
- **High**: Multiple detection rules covering the primary technique variants; tested against known real-world samples.
- **Medium**: Core detection present but limited sub-technique coverage; some variants may evade.
- **Partial**: Detection exists for high-level behavioral patterns but lacks technique-specific depth.
- **None**: No endpoint telemetry available for this tactic (e.g., pre-compromise Reconnaissance).

---

### Technique Deep Dives

#### T1059.001 — PowerShell

OpenArmor detects PowerShell abuse through four complementary mechanisms:

1. **Encoded command detection**: The `powershellEncodedCmd` pattern matches the `-enc`/`-EncodedCommand` flags plus any following Base64 string of 20+ characters. This catches standard Metasploit, Cobalt Strike, and Empire payloads without requiring deobfuscation.

2. **AMSI bypass attempts**: Patterns match known AMSI bypass strings in the PowerShell command line or child process arguments:
   ```json
   { "match": { "field": "cmdLine", "regex": "(?i)(amsicontext|amsiutils|amsiinitialized|\\[ref\\]\\.assembly|reflection\\.assembly::load)" } }
   ```

3. **Download cradle detection**: HTTP download patterns in PowerShell command lines:
   ```json
   { "match": { "field": "cmdLine", "regex": "(?i)(downloadstring|downloadfile|webclient|bitstransfer|invoke-webrequest|wget|curl)" } }
   ```

4. **Script block bypass**: Patterns for `-NonInteractive`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass` combinations that indicate covert execution.

PowerShell events are additionally enriched with `isPowerShellV2` (bool) since older versions lack script block logging support and are used to evade ScriptBlock logging.

---

#### T1055 — Process Injection

OpenArmor detects the three primary injection techniques through kernel-level observation:

- **DLL Injection** (`LLE_PROCESS_MEMORY_WRITE` + `CreateRemoteThread` pattern): The driver monitors cross-process writes followed within 2 seconds by thread creation in the same target process.
- **Process Hollowing**: Detection of `LLE_PROCESS_CREATE` with `isSuspended: true` followed by `LLE_PROCESS_MEMORY_WRITE` targeting the new process before it resumes.
- **Reflective DLL Injection**: Detection of `LLE_PROCESS_MEMORY_WRITE` followed by `LLE_PROCESS_MEMORY_READ` from the same source to the same target — the reflective loader lookup pattern.

All three generate `MLE_PROCESS_INJECTION` with `injectionTechnique` field identifying the specific variant.

---

#### T1003.001 — LSASS Memory Dump

Detection operates as a three-stage correlation:

**Stage 1**: `LLE_PROCESS_OPEN` with `targetProcessName=lsass.exe` and `accessMask` containing `PROCESS_VM_READ` or `PROCESS_QUERY_INFORMATION`. This alone is a `high` severity alert.

**Stage 2**: If Stage 1 is followed within 10 seconds by `LLE_PROCESS_MEMORY_READ` from the same source PID targeting LSASS, severity is elevated to `critical` and the `MLE_CREDENTIAL_ACCESS` event is generated.

**Stage 3**: If a file write event follows Stage 2 (the dump being written to disk), `LLE_FILE_CREATE` with `fileExtension=.dmp` from the same PID triggers quarantine of the dump file.

The `action: block` on Stage 1 prevents the handle from being opened at all for untrusted processes, stopping the attack before Stages 2 and 3 can occur.

---

#### T1547.001 — Registry Run Keys

All standard autostart registry locations are monitored via the `registryRunKeys` list. Detection includes:

- **HKCU and HKLM Run/RunOnce keys**: Primary persistence locations.
- **WOW6432Node variants**: 32-bit compatibility autostart keys used by some malware to evade 64-bit monitoring.
- **RunServices and RunServicesOnce**: Less common but actively exploited by older malware families.
- **Policies\Explorer\Run**: Group Policy-based autostart, rarely used legitimately.

The rule allowlists known-good values by full path (key path + value name combination) to permit legitimate software updates.

---

#### T1071 — Application Layer Protocol

C2 communication over HTTP/HTTPS/DNS is detected through behavioral analysis of network events:

- **Beaconing pattern**: Periodic `LLE_NETWORK_CONNECT_OUT` events to the same IP:port with a consistent interval (±15% jitter). The engine maintains per-process connection interval statistics.
- **Unusual user agent**: HTTP requests from non-browser processes with browser-like User-Agent strings indicate spoofing.
- **DNS tunneling**: `LLE_NETWORK_DNS_REQUEST` events with unusually long query names (>50 characters), high query frequency, or requests for rare TLDs.
- **HTTP over non-standard ports**: Outbound HTTP requests to ports other than 80, 8080, 8443.

---

#### T1113 — Screen Capture

Detection through kernel-level hooks on the primary screen capture APIs:

- `NtGdiBitBlt` / `NtGdiStretchBlt` with source DC being the desktop
- `NtUserPrintWindow` — Window bitmap capture
- `DwmGetDxSharedSurface` — Desktop Window Manager shared surface access

Each hook checks whether the calling process is a legitimate display-related application (Remote Desktop, video conferencing tools) using the `trustedSigners` list before generating an alert.

---

#### T1115 — Clipboard Data

`LLE_CLIPBOARD_GET` events are generated for any process that calls `GetClipboardData`. The detection rule triggers when:
- The accessing process is not in the foreground window's owner list
- The clipboard contains `CF_UNICODETEXT` data over 50 bytes (credential-sized)
- The accessing process is not in `browsers` or `officeApplications` lists

`LLE_CLIPBOARD_WATCH` events (SetClipboardViewer / AddClipboardFormatListener) from non-whitelisted processes generate immediate alerts as installing a clipboard monitor is rarely legitimate.

---

#### T1123 — Audio Capture

Audio capture detection uses ETW events from the `Microsoft-Windows-Audio` provider combined with hooks on:
- `waveInOpen` — Legacy WaveIn audio capture
- `IMMDeviceEnumerator::EnumAudioEndpoints` — Modern WASAPI enumeration
- `IAudioClient::Initialize` with `AUDCLNT_SHAREMODE_SHARED` in loopback mode

Legitimate applications (Teams, Zoom, WebEx) are allowlisted by signer name. Any audio capture from a process without a trusted signer generates an alert.

---

#### T1082 — System Information Discovery

Detection of post-exploitation reconnaissance through process and command-line monitoring:

```json
{
  "patterns": {
    "systemInfoDiscovery": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "match": {
          "field": "processName",
          "regex": "(?i)(systeminfo|whoami|ipconfig|arp|net|nltest|nslookup|ping|tracert|wmic|hostname|tasklist|sc|reg)\\.exe"
        }},
        { "not": { "in": { "field": "parentPath", "list": "fileWhitelist" } } },
        { "or": [
          { "in": { "field": "grandparentName", "list": "officeApplications" } },
          { "in": { "field": "parentName", "list": "scriptInterpreters" } },
          { "equals": { "field": "parentName", "value": "wmiprvse.exe" } }
        ]}
      ]
    }
  }
}
```

Multiple reconnaissance tools executed within a 2-minute window from the same PID lineage triggers an `MLE_DISCOVERY_ACTIVITY` event with elevated severity.

---

#### T1021 — Remote Services

Lateral movement via remote services is detected through network and process correlation:

- **SMB lateral movement**: `LLE_NETWORK_CONNECT_OUT` to port 445 from non-system processes, followed by `LLE_FILE_CREATE` on a UNC path (`\\target\share\...`).
- **RDP**: `LLE_NETWORK_CONNECT_OUT` to port 3389 from `mstsc.exe` or unexpected processes.
- **WinRM**: Connections to port 5985/5986, especially from `wsmprovhost.exe` spawning child processes.
- **PsExec pattern**: `LLE_SERVICE_CREATE` on a remote host followed by `LLE_FILE_CREATE` on an admin share path.

---

#### T1486 — Data Encrypted for Impact

Ransomware detection uses a multi-signal approach to minimize false positives:

1. **File write rate**: More than 50 file writes per 60-second window from a single process.
2. **Extension diversity**: The source process writes files with 3+ different extensions (suggesting encryption of heterogeneous file types).
3. **Rename pattern**: Files are renamed to a consistent new extension pattern (known ransomware extensions or random 5-8 character extensions).
4. **Shadow copy deletion**: Detection of `vssadmin delete shadows`, `wmic shadowcopy delete`, or direct `WMI Win32_ShadowCopy.Delete()` calls — a nearly universal ransomware pre-encryption step.
5. **Recovery inhibition**: Detection of `bcdedit /set {default} recoveryenabled no` or `wbadmin delete catalog`.

When 3 or more of these signals are observed within a 5-minute window, the response action is `terminate` + `isolateNetwork`.

---

#### T1562 — Impair Defenses

Detection of attempts to disable or tamper with security tooling:

- **EDR process targeting**: Any `LLE_PROCESS_OPEN` targeting the OpenArmor agent process (`edrav2.exe`) or driver service generates an immediate critical alert.
- **Security tool termination**: `LLE_PROCESS_CREATE` of `taskkill.exe` or `tskill.exe` targeting security product process names.
- **Firewall/Defender modification**: `netsh advfirewall` or `Set-MpPreference` commands adding exclusions.
- **Driver unload**: `LLE_DRIVER_UNLOAD` for the OpenArmor kernel driver triggers an immediate out-of-band alert to the management server.
- **Service modification**: `LLE_SERVICE_MODIFIED` on the OpenArmor agent service or Windows Defender service.

---

#### T1134 — Access Token Manipulation

Thread impersonation detection through `LLE_PROCESS_IMPERSONATION` events:

- **Token theft**: `ImpersonateLoggedOnUser` or `SetThreadToken` calls where the impersonated token belongs to a higher-privilege user (SYSTEM or Domain Admin).
- **Token duplication across sessions**: `DuplicateTokenEx` creating a primary token from an impersonation token in a different session.
- **Make-token**: `LogonUser` API calls followed immediately by `CreateProcessWithLogonW` — lateral movement using harvested credentials.

---

#### T1112 — Modify Registry

Registry modification monitoring extends beyond autostart keys to cover:

- **Security provider registration**: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` (enabling plaintext credential caching).
- **LSA protection**: `HKLM\SYSTEM\CurrentControlSet\Control\LSA\RunAsPPL` (disabling LSASS protection).
- **UAC bypass registry**: `HKCU\SOFTWARE\Classes\ms-settings\shell\open\command` and similar HKCU class hijacking keys.
- **COM hijacking**: `HKCU\SOFTWARE\Classes\CLSID\{*}\InprocServer32` writes.
- **AppInit_DLLs**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (DLL injection via registry).

---

#### T1053 — Scheduled Task/Job

Scheduled task detection through multiple data sources:

- **Schtasks.exe**: Process creation monitoring for `schtasks.exe /create` with command-line parsing for the `/TR` (task run) parameter.
- **Task Scheduler COM**: ETW events from `Microsoft-Windows-TaskScheduler` provider.
- **Registry persistence**: Scheduled tasks are backed by registry keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`.
- **XML task files**: File creation events in `C:\Windows\System32\Tasks\` and `C:\Windows\SysWOW64\Tasks\` directories.

The rule generates a `high` severity alert when a scheduled task is created to execute a non-system binary, especially from a script interpreter or Office application lineage.

---

### Sigma Rule Integration

OpenArmor events can be exported to Sigma format for integration with SIEMs (Splunk, Elastic SIEM, Microsoft Sentinel, Chronicle). The `edrcon` CLI provides a Sigma export command:

```cmd
REM Export OpenArmor policy rules as Sigma rules
edrcon sigma export --policy policy.json --output sigma_rules\

REM Export specific rule
edrcon sigma export --policy policy.json --rule rule_powershell_encoded \
  --output sigma_rules\powershell_encoded.yml

REM Convert OpenArmor event log to Sigma-compatible JSON
edrcon sigma convert-events --input events.json --output sigma_events.json
```

**Example Sigma Rule (Generated from OpenArmor policy)**

The following Sigma rule is automatically generated from the `rule_lsass_access` OpenArmor policy rule:

```yaml
title: LSASS Handle Opened for Memory Read
id: a8f63fde-4e2e-4f3d-9c8a-123456789abc
status: production
description: |
  A non-trusted process has opened a handle to lsass.exe with VM_READ or
  ALL_ACCESS permissions. This is the primary precursor to credential dumping
  attacks such as Mimikatz, Procdump-on-LSASS, and similar techniques.
  Detected by OpenArmor rule: rule_lsass_access
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://github.com/openarmor/openarmor
author: OpenArmor Security Team
date: 2025-01-15
tags:
  - attack.credential_access
  - attack.t1003.001
  - openarmor
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
      - 'C:\Program Files\Windows Defender\'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate security software performing LSASS monitoring
  - EDR agents
level: critical
fields:
  - SourceImage
  - TargetImage
  - GrantedAccess
  - CallTrace
```

To import OpenArmor events into Splunk for Sigma-based correlation:

```
index=openarmor sourcetype=openarmor_mle mleType=MLE_CREDENTIAL_ACCESS
| table timestamp, machineId, userName, processName, processPath, targetProcess, accessMask, severity, technique
| sort -timestamp
```

---

## Detection Examples

<picture>
  <source srcset="assets/Security_alert_OpenArmor_threat_…_202605010256.avif" type="image/avif">
  <img src="assets/Security_alert_OpenArmor_threat_…_202605010256.avif" alt="OpenArmor Threat Alert" width="100%">
</picture>

### Example: Detecting Mimikatz

Mimikatz is the most widely used credential dumping tool. Even when renamed, OpenArmor detects it through its behavioral signature rather than relying on file name alone.

**Full Event Chain**

```
Time+0.000s  LLE_PROCESS_CREATE
  pid:         1204  (cmd.exe)
  childPid:    4892
  childPath:   C:\Users\attacker\AppData\Local\Temp\svch0st.exe   ← renamed mimikatz
  childHash:   {sha256: 61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1}
  flsVerdict:  malicious   ← FLS identifies the hash despite filename change
  action:      ALERT (critical) — hash in knownMaliciousHashes list
  ruleName:    Credential Dumping Tool Executed

Time+0.450s  LLE_PROCESS_OPEN
  pid:         4892  (svch0st.exe)
  targetPid:   668
  targetProcessName: lsass.exe
  accessMask:  PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (0x1410)
  signerName:  [UNSIGNED]
  action:      BLOCK — handle open denied
  ruleName:    LSASS Handle Opened for Memory Read

Time+0.451s  MLE_CREDENTIAL_ACCESS generated
  severity:    critical
  technique:   T1003.001
  ruleName:    LSASS Credential Dumping Attempt
  action:      terminate (svch0st.exe PID 4892)
  responseActions: [terminateProcess, quarantineFile, captureProcessMemory]
  correlatedLLEs:  [LLE_PROCESS_CREATE, LLE_PROCESS_OPEN]
  description: Known credential dump tool (Mimikatz hash match) attempted to
               open LSASS handle. Handle blocked. Process terminated. File quarantined.
```

**Policy Rule That Catches This**

The detection is triggered by two cooperative rules:

```json
{
  "patterns": {
    "knownCredDumpHash": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_CREATE" } },
        { "in": { "field": "childHash.sha256", "list": "knownMaliciousHashes" } }
      ]
    },
    "lsassVmReadOpen": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_PROCESS_OPEN" } },
        { "equals": { "field": "targetProcessName", "value": "lsass.exe" } },
        { "or": [
          { "contains": { "field": "accessMask", "value": "PROCESS_VM_READ" } },
          { "gte": { "field": "accessMaskRaw", "value": 16 } }
        ]},
        { "not": { "in": { "field": "signerName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "rule_known_malicious_process": {
      "pattern": "knownCredDumpHash",
      "severity": "critical",
      "tactic": "Credential Access",
      "technique": "T1003",
      "ruleName": "Credential Dumping Tool Executed",
      "action": "block",
      "responseActions": ["terminateProcess", "quarantineFile"]
    },
    "rule_lsass_vm_read": {
      "pattern": "lsassVmReadOpen",
      "severity": "critical",
      "tactic": "Credential Access",
      "technique": "T1003.001",
      "ruleName": "LSASS Handle Opened for Memory Read",
      "action": "block",
      "responseActions": ["terminateProcess", "captureProcessMemory", "collectForensics"]
    }
  }
}
```

The layered approach ensures detection even if the hash is not in the database (the LSASS open rule fires independently) and even if the process is renamed or packed (the FLS verdict from hash lookup identifies it regardless of filename).

---

### Example: Detecting Cobalt Strike Beacon

Cobalt Strike is the most widely abused post-exploitation framework. Beacons are injected into legitimate processes and communicate with a team server over HTTP/HTTPS.

**Full Event Chain**

```
Time+0.000s  LLE_PROCESS_CREATE
  pid:         3560  (spear_phishing_doc.exe, from email attachment execution)
  childPid:    5124
  childPath:   C:\Windows\System32\rundll32.exe   ← spawnto process (injected)
  childCmdLine: rundll32.exe
  flsVerdict:  clean   ← rundll32 itself is legitimate

Time+0.200s  LLE_PROCESS_MEMORY_WRITE
  pid:         3560  (attacker dropper)
  targetPid:   5124  (rundll32.exe)
  baseAddress: 0x7ff123400000
  regionSize:  245760          ← 240KB shellcode written
  targetRegionProtect: PAGE_READWRITE → changes to PAGE_EXECUTE_READ

Time+0.250s  LLE_PROCESS_CREATE  (CreateRemoteThread in rundll32)
  ALERT: MLE_PROCESS_INJECTION generated
  severity:    critical
  technique:   T1055
  injectionTechnique: classic-dll-injection
  sourceProcess: 3560 (spear_phishing_doc.exe)
  targetProcess: 5124 (rundll32.exe)

Time+12.000s LLE_NETWORK_CONNECT_OUT  (first beacon check-in)
  pid:         5124  (rundll32.exe, now Beacon)
  remoteIp:    185.220.101.45
  remotePort:  443
  protocol:    tcp
  sni:         updates.microsoft-cdn.com   ← domain fronting / C2 domain
  bytesTransferred: 843

Time+72.000s LLE_NETWORK_CONNECT_OUT  (beacon interval ~60s)
  pid:         5124
  remoteIp:    185.220.101.45
  remotePort:  443
  beaconIntervalDetected: 60s (±8%)
  ALERT: MLE_C2_BEACONING generated
  severity:    critical
  technique:   T1071.001
  ruleName:    Suspected Cobalt Strike Beacon (Periodic C2)
  action:      block + isolateNetwork
```

**Policy Rule for Beacon Detection**

```json
{
  "patterns": {
    "processInjectionWithNetwork": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_NETWORK_CONNECT_OUT" } },
        { "equals": { "field": "injectedProcess", "value": "true" } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "or": [
          { "equals": { "field": "remotePort", "value": 443 } },
          { "equals": { "field": "remotePort", "value": 80 } },
          { "equals": { "field": "remotePort", "value": 8080 } }
        ]},
        { "gt": { "field": "beaconIntervalConsistency", "value": 80 } }
      ]
    }
  },
  "events": {
    "rule_beacon_c2": {
      "pattern": "processInjectionWithNetwork",
      "severity": "critical",
      "tactic": "Command and Control",
      "technique": "T1071.001",
      "ruleName": "Suspected C2 Beaconing from Injected Process",
      "description": "An injected process is making periodic outbound HTTPS connections with consistent timing — characteristic of Cobalt Strike, Metasploit Meterpreter, or similar C2 frameworks.",
      "action": "block",
      "responseActions": ["terminateProcess", "isolateNetwork", "captureNetworkTraffic", "captureProcessMemory"]
    }
  }
}
```

The `injectedProcess` field is a derived field set by the enrichment stage when a process was the previous target of a `LLE_PROCESS_MEMORY_WRITE` cross-process operation. The `beaconIntervalConsistency` field (0–100) measures the regularity of connection intervals over the past 10 connections.

---

### Example: Detecting Ransomware

The following example traces a complete ransomware execution from initial launch through file encryption to detection and termination.

**Full Event Chain**

```
Time+0.000s  LLE_PROCESS_CREATE
  pid:         7788
  childPid:    9012
  childPath:   C:\Users\user\Downloads\invoice_april.exe
  childHash:   {sha256: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e...}
  flsVerdict:  unknown   ← New sample, not in FLS database
  valkyrieVerdict: pending   ← Submitted to sandbox

Time+0.500s  LLE_PROCESS_CREATE  (vssadmin launched by ransomware)
  pid:         9012
  childPid:    9156
  childPath:   C:\Windows\System32\vssadmin.exe
  childCmdLine: vssadmin.exe delete shadows /all /quiet
  ALERT: MLE_SHADOW_COPY_DELETION (severity=critical)

Time+1.200s  LLE_FILE_OPEN × 847  (file enumeration — 847 opens in 2s)
  pid:         9012
  filePath:    C:\Users\user\Documents\*.docx, *.xlsx, *.pdf ...
  fileEnumerationRate: 423 files/sec

Time+3.500s  LLE_FILE_WRITE × 212  (encryption begins)
  pid:         9012
  filePath:    C:\Users\user\Documents\report_q1.docx
  fileSize:    48293 → 49152 (rounded up — encryption padding)
  entropy:     7.98 bits/byte   ← Near-maximum entropy = encrypted content

Time+4.100s  LLE_FILE_RENAME × 212
  pid:         9012
  oldFilePath: C:\Users\user\Documents\report_q1.docx
  newFilePath: C:\Users\user\Documents\report_q1.docx.LOCKED
  processFileWriteCount60s: 212   ← Exceeds threshold of 50

  TRIGGER: MLE_RANSOMWARE_BEHAVIOR generated
  severity:    critical
  technique:   T1486
  ruleName:    Mass File Encryption — Ransomware Behavior
  filesAffectedCount: 212
  fileExtensionsObserved: [".docx", ".xlsx", ".pdf", ".png", ".jpg"]
  newExtensionPattern: ".LOCKED"
  estimatedEncryptionRate: 180 MB/min
  action:      terminate + isolateNetwork + snapshotFilesystem

Time+4.105s  RESPONSE ACTIONS EXECUTED
  - Process 9012 (invoice_april.exe) TERMINATED
  - Network interface isolated (all traffic blocked except management channel)
  - Filesystem snapshot initiated (VSS if available, else file catalog)
  - File C:\Users\user\Downloads\invoice_april.exe QUARANTINED
  - Alert sent to management server (out-of-band, management channel exempt from isolation)
  - Administrator notification: EMAIL + SIEM alert

Time+4.200s  valkyrieVerdict: malicious (score: 98)
  - Quarantine confirmed
  - Valkyrie hash added to knownMaliciousHashes list (pushed to all agents within 60s)
```

**Policy Rules Involved**

The ransomware detection chain involves three cooperating rules:

1. `rule_shadow_copy_deletion` — Fires immediately on VSS deletion command (severity: critical)
2. `rule_high_entropy_file_writes` — Fires when file write operations produce near-maximum entropy output (severity: high)
3. `rule_ransomware_behavior` — The primary ransomware rule; fires on the mass rename threshold (severity: critical, action: terminate + isolateNetwork)

---

### Example: Detecting Lateral Movement

**Full Event Chain**

```
Time+0.000s  LLE_NETWORK_CONNECT_OUT
  pid:         4220  (beacon in svchost.exe, post-injection)
  remoteIp:    10.10.10.50   ← Internal target host
  remotePort:  445
  protocol:    tcp
  appProtocol: smb

Time+0.450s  LLE_PROCESS_CREATE
  pid:         4220  (svchost.exe beacon)
  childPid:    4488
  childPath:   C:\Windows\System32\cmd.exe
  childCmdLine: cmd.exe /c copy \\10.10.10.50\ADMIN$\system32\ C:\Windows\temp\tool.exe

Time+0.800s  LLE_FILE_CREATE
  pid:         4488  (cmd.exe)
  filePath:    \\10.10.10.50\ADMIN$\system32\svch0st.exe   ← Drop on remote admin share
  fileSize:    892416

Time+1.200s  LLE_SERVICE_CREATE
  pid:         4220  (beacon)
  serviceName: WindowsUpdateHelper
  serviceBinaryPath: C:\Windows\System32\svch0st.exe
  targetMachine: 10.10.10.50
  ALERT: MLE_LATERAL_MOVEMENT generated (severity=critical)

Full MLE_LATERAL_MOVEMENT event:
  mleType:              MLE_LATERAL_MOVEMENT
  severity:             critical
  tactic:               Lateral Movement
  technique:            T1021.002
  ruleName:             SMB Lateral Movement — Remote Service Creation
  sourceHost:           WORKSTATION01
  destinationHost:      10.10.10.50
  lateralMovementVector: smb
  adminShareAccessed:   true
  remoteServiceCreated: true
  droppedFilePath:      \\10.10.10.50\ADMIN$\system32\svch0st.exe
  serviceName:          WindowsUpdateHelper
  action:               alert + blockConnection
  responseActions:      [blockSMBToTarget, collectNetworkCapture, alertSOC]
```

**Policy Rule for Lateral Movement**

```json
{
  "patterns": {
    "smbLateralMovement": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_NETWORK_CONNECT_OUT" } },
        { "equals": { "field": "remotePort", "value": 445 } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "not": { "in": { "field": "signerName", "list": "trustedSigners" } } },
        { "equals": { "field": "injectedProcess", "value": "true" } }
      ]
    },
    "adminShareFileWrite": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_FILE_CREATE" } },
        { "match": { "field": "filePath", "regex": "^\\\\\\\\[^\\\\]+\\\\(ADMIN|C|D|E)\\$\\\\" } },
        { "in": { "field": "fileExtension", "list": "infectibleExtensions" } }
      ]
    },
    "remoteServiceInstall": {
      "and": [
        { "equals": { "field": "baseType", "value": "LLE_SERVICE_CREATE" } },
        { "not": { "in": { "field": "processPath", "list": "fileWhitelist" } } },
        { "startsWith": { "field": "serviceBinaryPath", "value": "C:\\Windows\\" } },
        { "not": { "in": { "field": "signerName", "list": "trustedSigners" } } }
      ]
    }
  },
  "events": {
    "rule_smb_lateral_movement": {
      "pattern": "smbLateralMovement",
      "severity": "high",
      "tactic": "Lateral Movement",
      "technique": "T1021.002",
      "ruleName": "SMB Connection from Injected Process",
      "action": "alert"
    },
    "rule_admin_share_drop": {
      "pattern": "adminShareFileWrite",
      "severity": "critical",
      "tactic": "Lateral Movement",
      "technique": "T1021.002",
      "ruleName": "Executable Dropped to Administrative Share",
      "action": "block",
      "responseActions": ["blockSMBConnection", "collectNetworkCapture"]
    },
    "rule_remote_service_install": {
      "pattern": "remoteServiceInstall",
      "severity": "critical",
      "tactic": "Lateral Movement",
      "technique": "T1021.002",
      "ruleName": "Remote Service Created by Untrusted Process",
      "action": "alert",
      "responseActions": ["alertSOC", "collectServiceDetails", "blockSMBToTarget"]
    }
  }
}
```

The three lateral movement rules cooperate: the first fires on the initial SMB connection (providing early warning), the second fires when the payload is dropped on the admin share (actionable evidence), and the third fires when the remote service is installed (confirming the lateral movement is complete). Each successive rule elevates the severity and response actions, enabling the SOC to intervene at the earliest possible stage.

---

*End of Section 4*
## Cloud Integration & Telemetry

<picture>
  <source srcset="assets/Cloud_communication_architecture…_202605010255.avif" type="image/avif">
  <img src="assets/Cloud_communication_architecture…_202605010255.avif" alt="Cloud Communication Architecture" width="100%">
</picture>

OpenArmor's cloud integration layer provides a flexible, backend-agnostic telemetry pipeline that enables real-time event streaming from endpoints to centralized analysis platforms. Designed for enterprise-scale deployments, the cloud subsystem handles batch assembly, compression, encryption, retry logic, and offline buffering without impacting endpoint performance.

The telemetry pipeline operates as a dedicated subsystem within `edrsvc.exe`. Events generated by the kernel driver, process monitor, network monitor, and file monitor are routed through an internal message bus, enriched with contextual metadata, serialized to JSON, batched, and forwarded to the configured cloud backend. The entire pipeline is asynchronous — event collection is never blocked by upload operations.

### Supported Backends

| Backend | Status | Transport | Auth Method | Notes |
|---|---|---|---|---|
| AWS Kinesis Data Firehose | Production | HTTPS | IAM credentials / instance role | Recommended for AWS-native environments |
| Self-Hosted ELK Stack | Production | HTTPS | Basic auth / API key | Elasticsearch 7.x and 8.x supported |
| Comodo Dragon Platform | Production | HTTPS | Enrollment token | Native integration with commercial portal |
| HTTP REST (Generic) | Production | HTTPS / HTTP | Bearer token / Basic / mTLS | For custom SIEM and data lake integrations |
| Google Cloud Pub/Sub | Planned (v2.6) | HTTPS | Service account JSON | Roadmap item |
| Azure Event Hubs | Planned (v3.0) | AMQP / HTTPS | Connection string / AAD | Roadmap item |

All production backends support TLS 1.2 and above. Certificate verification is enforced by default and can be configured to use a custom CA bundle for environments with internal PKI.

---

### AWS Kinesis Data Firehose

AWS Kinesis Data Firehose is the recommended cloud backend for organizations running AWS-native infrastructure. OpenArmor streams events directly to a Firehose delivery stream, which can route data to S3, Redshift, OpenSearch Service, or Splunk.

#### Configuration

Add the following block to `edrsvc.json`:

```json
{
  "cloud": {
    "provider": "aws",
    "firehose": {
      "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
      "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "deliveryStream": "openarmor-events",
      "region": "us-east-1",
      "batchSize": 500,
      "batchIntervalMs": 5000,
      "compressionEnabled": true,
      "tlsVerify": true,
      "proxyUrl": "",
      "offlineBufferMaxMb": 500,
      "offlineBufferPath": "C:\\ProgramData\\OpenArmor\\buffer"
    }
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `accessKeyId` | string | — | AWS access key ID. Leave blank to use EC2 instance role or ECS task role. |
| `secretAccessKey` | string | — | AWS secret access key. Leave blank when using instance/task role. |
| `deliveryStream` | string | — | Name of the Kinesis Firehose delivery stream. |
| `region` | string | `us-east-1` | AWS region where the delivery stream is hosted. |
| `batchSize` | integer | `500` | Maximum number of events per PutRecordBatch call (max 500, AWS limit). |
| `batchIntervalMs` | integer | `5000` | Maximum time in milliseconds between batch uploads, regardless of batch size. |
| `compressionEnabled` | boolean | `true` | Gzip-compress payloads before upload. Reduces data transfer costs. |
| `tlsVerify` | boolean | `true` | Enforce TLS certificate verification. |
| `proxyUrl` | string | `""` | Optional HTTP/HTTPS proxy for outbound connections. |
| `offlineBufferMaxMb` | integer | `500` | Maximum local disk buffer when cloud is unreachable. |
| `offlineBufferPath` | string | `C:\ProgramData\OpenArmor\buffer` | Directory for offline buffer files. |

#### IAM Policy — Least Privilege

Create a dedicated IAM user or role with the following policy. Do not grant broader permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OpenArmorFirehosePut",
      "Effect": "Allow",
      "Action": [
        "firehose:PutRecord",
        "firehose:PutRecordBatch"
      ],
      "Resource": "arn:aws:firehose:us-east-1:123456789012:deliverystream/openarmor-events"
    }
  ]
}
```

For EC2-based deployments, attach this policy to an IAM instance role and omit `accessKeyId` and `secretAccessKey` from the configuration. OpenArmor will automatically use the EC2 Instance Metadata Service (IMDSv2) to retrieve temporary credentials.

#### Firehose Delivery Stream Setup

1. Open the AWS Console and navigate to **Kinesis** > **Data Firehose**.
2. Click **Create delivery stream**.
3. Set **Source** to `Direct PUT`.
4. Set **Destination** to `Amazon S3` (or OpenSearch Service, Splunk, etc.).
5. Configure **S3 bucket** as `s3://your-security-data-bucket/openarmor/`.
6. Enable **Dynamic Partitioning** with the expression `!{partitionKeyFromQuery:endpointId}` to partition by endpoint.
7. Set **Buffer size** to `128 MB` and **Buffer interval** to `300 seconds`.
8. Enable **GZIP compression** for S3 objects.
9. Enable **Server-side encryption** using an AWS KMS key.
10. Note the delivery stream ARN and use the stream name in your configuration.

#### S3 Destination Layout

Events land in S3 with the following prefix structure:

```
s3://your-bucket/openarmor/
  year=2024/
    month=01/
      day=15/
        hour=14/
          endpoint-uuid-1/
            openarmor-events-1-2024-01-15-14-00-00-abc123.json.gz
```

#### Kinesis Analytics Integration

For real-time stream analytics, attach a Kinesis Data Analytics application to the same stream:

1. Create a **Kinesis Data Analytics** application (Apache Flink).
2. Set input to your `openarmor-events` Firehose stream.
3. Use SQL or Flink jobs to detect patterns such as:
   - High-frequency process creation from a single endpoint
   - Lateral movement indicators (multiple endpoints, same credential)
   - Anomalous network destinations from system processes

#### Throughput Characteristics

- Each PutRecordBatch call supports up to 500 records and 4 MB total payload.
- At default settings (`batchSize: 500`, `batchIntervalMs: 5000`), an endpoint generating 100 events/second will produce approximately 72,000 events/minute, uploaded in 144 batches.
- AWS Firehose default limits: 2,000 records/second per stream (can be raised via support request).
- Estimated cost at 10,000 events/hour/endpoint: approximately $0.02/day per endpoint at standard Firehose pricing.

---

### Self-Hosted ELK Configuration

The Elasticsearch / Logstash / Kibana (ELK) stack integration enables organizations to keep all telemetry data on-premises. OpenArmor writes events directly to Elasticsearch using the bulk indexing API, bypassing Logstash for lower latency.

#### Configuration

```json
{
  "cloud": {
    "provider": "elk",
    "elasticsearch": {
      "endpoint": "https://your-elk:9200",
      "index": "openarmor-events",
      "username": "openarmor_writer",
      "password": "CHANGE_THIS_STRONG_PASSWORD",
      "tlsCert": "C:\\OpenArmor\\certs\\ca.pem",
      "tlsVerify": true,
      "batchSize": 1000,
      "batchIntervalMs": 3000,
      "compressionEnabled": true,
      "apiKey": "",
      "indexSuffix": "daily"
    },
    "heartbeatIntervalSec": 30,
    "offlineBufferMaxMb": 500,
    "offlineBufferPath": "C:\\ProgramData\\OpenArmor\\buffer"
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | — | Full URL of your Elasticsearch node or load balancer. |
| `index` | string | `openarmor-events` | Base index name. Suffix is appended based on `indexSuffix`. |
| `username` | string | — | Elasticsearch username for basic authentication. |
| `password` | string | — | Elasticsearch password. Use environment variable injection in production. |
| `tlsCert` | string | — | Path to CA certificate PEM file for TLS verification. |
| `tlsVerify` | boolean | `true` | Enforce TLS certificate verification. |
| `batchSize` | integer | `1000` | Number of events per bulk request. |
| `batchIntervalMs` | integer | `3000` | Maximum time between bulk uploads. |
| `compressionEnabled` | boolean | `true` | Use HTTP compression for bulk requests. |
| `apiKey` | string | `""` | Elasticsearch API key. If set, overrides `username`/`password`. |
| `indexSuffix` | string | `daily` | Index rotation: `daily` (`-YYYY.MM.DD`), `monthly` (`-YYYY.MM`), `none`. |
| `heartbeatIntervalSec` | integer | `30` | How often to send a heartbeat ping to Elasticsearch. |
| `offlineBufferMaxMb` | integer | `500` | Maximum offline buffer size. |

#### Elasticsearch Role for openarmor_writer

Create a minimal role in Kibana (Stack Management > Roles):

```json
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["openarmor-*"],
      "privileges": ["create_index", "index", "write", "view_index_metadata"]
    }
  ]
}
```

#### Index Template

Apply this index template before the first event arrives to ensure correct field mappings:

```bash
curl -X PUT "https://your-elk:9200/_index_template/openarmor" \
  -H "Content-Type: application/json" \
  -u openarmor_admin:password \
  -d '{
    "index_patterns": ["openarmor-*"],
    "template": {
      "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 1,
        "index.lifecycle.name": "openarmor-ilm",
        "index.lifecycle.rollover_alias": "openarmor"
      },
      "mappings": {
        "properties": {
          "timestamp":    { "type": "date", "format": "epoch_millis" },
          "endpointId":   { "type": "keyword" },
          "hostname":     { "type": "keyword" },
          "baseType":     { "type": "integer" },
          "pid":          { "type": "integer" },
          "processName":  { "type": "keyword" },
          "processPath":  { "type": "keyword" },
          "cmdLine":      { "type": "text" },
          "severity":     { "type": "keyword" },
          "mitre.tactic": { "type": "keyword" },
          "mitre.technique": { "type": "keyword" }
        }
      }
    }
  }'
```

#### ILM Policy

Configure Index Lifecycle Management to control disk usage:

```bash
curl -X PUT "https://your-elk:9200/_ilm/policy/openarmor-ilm" \
  -H "Content-Type: application/json" \
  -u openarmor_admin:password \
  -d '{
    "policy": {
      "phases": {
        "hot":    { "min_age": "0ms",  "actions": { "rollover": { "max_size": "50gb", "max_age": "7d" } } },
        "warm":   { "min_age": "7d",   "actions": { "shrink": { "number_of_shards": 1 }, "forcemerge": { "max_num_segments": 1 } } },
        "cold":   { "min_age": "30d",  "actions": { "freeze": {} } },
        "delete": { "min_age": "90d",  "actions": { "delete": {} } }
      }
    }
  }'
```

---

### HTTP REST (Generic)

The generic HTTP REST backend allows OpenArmor to forward events to any SIEM, data lake, or custom webhook endpoint that accepts JSON over HTTP/HTTPS.

#### Configuration

```json
{
  "cloud": {
    "provider": "http",
    "http": {
      "endpoint": "https://your-siem.example.com/api/v1/events",
      "method": "POST",
      "authType": "bearer",
      "bearerToken": "YOUR_API_TOKEN",
      "basicUsername": "",
      "basicPassword": "",
      "mtlsCert": "",
      "mtlsKey": "",
      "customHeaders": {
        "X-Source": "openarmor",
        "X-Tenant": "acme-corp"
      },
      "batchSize": 200,
      "batchIntervalMs": 5000,
      "timeoutMs": 10000,
      "retryCount": 5,
      "retryBackoffMs": 1000,
      "retryBackoffMultiplier": 2.0,
      "tlsVerify": true,
      "tlsCaCert": "C:\\OpenArmor\\certs\\ca.pem"
    },
    "offlineBufferMaxMb": 500,
    "offlineBufferPath": "C:\\ProgramData\\OpenArmor\\buffer"
  }
}
```

#### Authentication Options

| `authType` | Description | Required Fields |
|---|---|---|
| `bearer` | Bearer token in `Authorization` header | `bearerToken` |
| `basic` | HTTP Basic Authentication | `basicUsername`, `basicPassword` |
| `mtls` | Mutual TLS client certificate | `mtlsCert`, `mtlsKey` |
| `none` | No authentication (use only on trusted networks) | — |

#### Event Payload Format

Events are sent as a JSON array in the request body:

```json
{
  "source": "openarmor",
  "version": "2.5",
  "batchId": "uuid-v4",
  "sentAt": 1714500000000000,
  "events": [ ... ]
}
```

#### Retry Logic

The HTTP backend implements exponential backoff with jitter:

- First retry after `retryBackoffMs` milliseconds (default: 1,000 ms)
- Each subsequent retry multiplies the delay by `retryBackoffMultiplier` (default: 2.0)
- Maximum retries: `retryCount` (default: 5)
- After all retries are exhausted, the batch is written to the offline buffer

Retry is triggered on HTTP 5xx responses, connection timeouts, and DNS failures. HTTP 4xx responses (client errors) are logged and the batch is dropped (not retried), except for HTTP 429 (Too Many Requests), which triggers backoff.

---

### Enrollment & Device Management

Endpoints connect to a central management server for policy distribution, configuration updates, and enrollment token validation.

```cmd
REM Enroll endpoint with management server
edrcon enroll --server https://management.example.com --token YOUR_ENROLLMENT_TOKEN

REM Verify enrollment status
edrcon dump --section cloud

REM Re-enroll (rotate endpoint certificate and re-register)
edrcon enroll --renew

REM Enroll with custom endpoint ID (for migration scenarios)
edrcon enroll --server https://management.example.com --token YOUR_TOKEN --endpoint-id existing-uuid

REM Enroll in offline/air-gapped mode using a pre-provisioned identity bundle
edrcon enroll --offline --bundle C:\install\endpoint-identity.bundle
```

The enrollment process performs the following steps:

1. The endpoint generates an RSA-2048 key pair and a certificate signing request (CSR).
2. The CSR and enrollment token are sent to the management server over mTLS.
3. The server validates the token, signs the certificate, and returns a signed endpoint certificate along with the initial policy bundle.
4. The endpoint stores its private key in the Windows Data Protection API (DPAPI) protected store.
5. All subsequent management plane communication uses the signed certificate for mutual authentication.

---

### Telemetry Event Format

Every event sent to the cloud backend follows a common envelope schema, with event-type-specific fields in the payload:

```json
{
  "version": "2.5",
  "endpointId": "3f8a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "hostname": "WORKSTATION01",
  "domain": "CORP",
  "osVersion": "Windows 10 22H2 19045.3930",
  "agentVersion": "2.5.1.1000",
  "timestamp": 1714500000000000,
  "baseType": 101,
  "eventTypeName": "LLE_PROCESS_CREATE",
  "pid": 1234,
  "processName": "powershell.exe",
  "processPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "processHash": {
    "sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    "md5": "112233445566778899aabbccddeeff00"
  },
  "cmdLine": "powershell.exe -EncodedCommand SABlAGwAbABvAA==",
  "parentPid": 5678,
  "parentName": "winword.exe",
  "parentPath": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "parentHash": {
    "sha256": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
    "md5": "aabbccddeeff00112233445566778899"
  },
  "userName": "CORP\\jsmith",
  "userSid": "S-1-5-21-1234567890-123456789-1234567890-1001",
  "sessionId": 1,
  "severity": "high",
  "mitre": {
    "tactic": "Execution",
    "technique": "T1059.001",
    "techniqueName": "PowerShell"
  },
  "policyMatch": "suspicious_powershell_encoded_command",
  "flsVerdict": "unknown",
  "signatureStatus": "signed",
  "signaturePublisher": "Microsoft Corporation",
  "integrityLevel": "high",
  "isElevated": true,
  "networkInfo": null,
  "fileInfo": null
}
```

#### Base Event Types (LLE — Low Level Events)

| `baseType` | `eventTypeName` | Description |
|---|---|---|
| 100 | `LLE_PROCESS_CREATE` | New process creation |
| 101 | `LLE_PROCESS_TERMINATE` | Process exit |
| 200 | `LLE_MODULE_LOAD` | DLL/module loaded into process |
| 300 | `LLE_FILE_CREATE` | File creation |
| 301 | `LLE_FILE_MODIFY` | File modification |
| 302 | `LLE_FILE_DELETE` | File deletion |
| 303 | `LLE_FILE_RENAME` | File rename |
| 400 | `LLE_REGISTRY_CREATE` | Registry key/value creation |
| 401 | `LLE_REGISTRY_MODIFY` | Registry value modification |
| 402 | `LLE_REGISTRY_DELETE` | Registry key/value deletion |
| 500 | `LLE_NETWORK_CONNECT` | Outbound network connection |
| 501 | `LLE_NETWORK_LISTEN` | Process opened listening socket |
| 502 | `LLE_DNS_REQUEST` | DNS query from process |
| 600 | `LLE_INJECTION_DETECTED` | Code injection detected |
| 700 | `LLE_THREAT_ALERT` | Policy match / threat detection |
| 800 | `LLE_CLIPBOARD_ACCESS` | Process accessed clipboard |
| 900 | `LLE_KEYBOARD_STATE` | Keyboard capture detected |

---

### Offline Buffering

When the cloud backend is unreachable, OpenArmor writes events to an encrypted local buffer to prevent data loss. The offline buffer is a write-ahead log (WAL) stored in the `offlineBufferPath` directory.

**Buffer behavior:**

- Events are written to disk in 4 MB segment files as they arrive.
- Segment files are encrypted using a per-device AES-256 key stored in DPAPI.
- The buffer maintains a write pointer and a read pointer. On reconnection, the read pointer advances as segments are successfully uploaded.
- Once uploaded and acknowledged by the backend, segment files are deleted.
- If the buffer reaches `offlineBufferMaxMb`, the oldest segments are rotated out (FIFO). A warning is emitted to the service log.
- Buffer integrity is verified using SHA-256 checksums on each segment header.

**Data integrity guarantees:**

- Events are not removed from the buffer until the backend returns a successful acknowledgment (HTTP 200, Firehose `RequestResponses` with no errors).
- In the event of a service restart, the buffer resumes from the last successfully uploaded position.
- Duplicate delivery is possible in edge cases (crash between upload success and pointer advance). Consumers should implement idempotency using the `batchId` field.

---

## Configuration Reference

### edrsvc.json — Complete Reference

The primary configuration file for the OpenArmor EDR service. Located at `C:\ProgramData\OpenArmor\edrsvc.json` by default. Changes require a service restart unless `autoReload` is enabled for the relevant subsystem.

```json
{
  "log": {
    "level": "info",
    "file": "C:\\ProgramData\\OpenArmor\\logs\\edrsvc.log",
    "maxSizeMb": 100,
    "maxFiles": 5,
    "structured": true,
    "consoleOutput": false
  },
  "service": {
    "name": "OpenArmorEDR",
    "displayName": "OpenArmor EDR Service",
    "description": "OpenArmor Endpoint Detection and Response",
    "startType": "automatic",
    "recoveryActions": "restart"
  },
  "sysmon": {
    "filterPort": "\\\\.\\OpenArmorFltPort",
    "workerThreads": 2,
    "bufferSizeMin": 4096,
    "bufferSizeMax": 1048576,
    "maxPendingEvents": 50000,
    "droppedEventThreshold": 100
  },
  "procmon": {
    "enabled": true,
    "queueSize": 10000,
    "sendTimeoutMs": 5000,
    "injectionEnabled": true,
    "injectionTimeout": 3000,
    "eventTimeouts": {
      "keyboardState": 60000,
      "clipboardData": 5000
    },
    "excludedPids": [],
    "excludedPaths": [
      "C:\\Windows\\System32\\svchost.exe"
    ]
  },
  "netmon": {
    "enabled": true,
    "captureInbound": false,
    "captureLoopback": false,
    "excludedPorts": [80, 443],
    "excludedProcesses": []
  },
  "filemon": {
    "enabled": true,
    "watchExtensions": [".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"],
    "excludedPaths": [
      "C:\\Windows\\WinSxS\\"
    ]
  },
  "regmon": {
    "enabled": true,
    "watchHives": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "excludedPaths": []
  },
  "cloud": {
    "provider": "aws",
    "firehose": { "...": "see AWS section" }
  },
  "policy": {
    "file": "C:\\ProgramData\\OpenArmor\\policy.json",
    "autoReload": true,
    "reloadIntervalSec": 60,
    "signatureVerification": true,
    "signingCert": "C:\\ProgramData\\OpenArmor\\certs\\policy-signing.pem"
  },
  "dataProviders": {
    "processCache": {
      "ttlSec": 600,
      "maxEntries": 10000,
      "enrichWithParentChain": true,
      "maxParentDepth": 10
    },
    "fileCache": {
      "ttlSec": 300,
      "maxEntries": 50000,
      "hashOnFirstSeen": true
    },
    "networkCache": {
      "ttlSec": 60,
      "maxEntries": 100000
    },
    "fls": {
      "enabled": true,
      "endpoint": "https://fls.comodo.com/api/v2",
      "timeoutMs": 2000,
      "cacheResultSec": 3600
    }
  },
  "selfProtection": {
    "enabled": true,
    "protectFiles": true,
    "protectRegistry": true,
    "protectProcess": true,
    "protectDriver": true,
    "allowedAdminSids": [
      "S-1-5-32-544"
    ]
  },
  "diagnostics": {
    "enableCrashDumps": true,
    "crashDumpPath": "C:\\ProgramData\\OpenArmor\\crashes",
    "metricsExportEnabled": false,
    "metricsPort": 9090
  }
}
```

#### Field Reference — `log`

| Field | Type | Default | Valid Values | Description |
|---|---|---|---|---|
| `level` | string | `info` | `trace`, `debug`, `info`, `warn`, `error` | Minimum log severity to emit. `trace` produces very high volume. |
| `file` | string | `C:\ProgramData\OpenArmor\logs\edrsvc.log` | Any valid path | Log file path. Directory must exist. |
| `maxSizeMb` | integer | `100` | 1–10240 | Maximum size of a single log file before rotation. |
| `maxFiles` | integer | `5` | 1–100 | Number of rotated log files to retain. |
| `structured` | boolean | `true` | `true`, `false` | Emit JSON-structured log lines for machine parsing. |
| `consoleOutput` | boolean | `false` | `true`, `false` | Also write logs to stdout (useful for `edrcon run` interactive mode). |

#### Field Reference — `sysmon`

| Field | Type | Default | Valid Values | Description |
|---|---|---|---|---|
| `filterPort` | string | `\\.\OpenArmorFltPort` | — | Named pipe for kernel filter driver communication. Do not change. |
| `workerThreads` | integer | `2` | 1–32 | Number of threads processing kernel events. Increase for high event volume endpoints (servers, CI/CD agents). |
| `bufferSizeMin` | integer | `4096` | 4096–65536 | Minimum kernel event buffer size in bytes. |
| `bufferSizeMax` | integer | `1048576` | 65536–16777216 | Maximum kernel event buffer size. Controls memory allocation ceiling. |
| `maxPendingEvents` | integer | `50000` | 1000–500000 | Queue depth before events are dropped. Increase to handle bursts. |
| `droppedEventThreshold` | integer | `100` | 1–10000 | Number of dropped events per minute before a warning is logged. |

#### Field Reference — `procmon`

| Field | Type | Default | Valid Values | Description |
|---|---|---|---|---|
| `enabled` | boolean | `true` | `true`, `false` | Enable process monitor module. |
| `queueSize` | integer | `10000` | 100–1000000 | Internal event queue depth for process events. |
| `sendTimeoutMs` | integer | `5000` | 100–60000 | Timeout for sending an event from injected DLL back to service. |
| `injectionEnabled` | boolean | `true` | `true`, `false` | Enable edrpm.dll injection into monitored processes. Required for clipboard and keyboard monitoring. |
| `excludedPids` | array | `[]` | PID list | Processes excluded from monitoring by PID. Intended for temporary exclusions only. |
| `excludedPaths` | array | `[]` | Path list | Processes excluded from monitoring by image path. Supports wildcards (`*`). |

#### Field Reference — `selfProtection`

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Master switch for self-protection. Disabling exposes the EDR to tampering. |
| `protectFiles` | boolean | `true` | Prevent unauthorized modification or deletion of EDR binary files. |
| `protectRegistry` | boolean | `true` | Prevent unauthorized modification of EDR service and driver registry keys. |
| `protectProcess` | boolean | `true` | Restrict handle access to `edrsvc.exe` (prevents process injection and termination). |
| `protectDriver` | boolean | `true` | Prevent unloading of `edrdrv.sys` from user mode. |
| `allowedAdminSids` | array | `["S-1-5-32-544"]` | SIDs allowed to bypass protection (e.g., for legitimate administrative operations). |

---

## Performance Tuning

### Baseline Metrics

The following table shows typical resource overhead measured on a mid-range endpoint (Intel Core i5-10th Gen, 16 GB RAM, SSD) running Windows 10 22H2 with default configuration:

| Metric | Typical | High Load | Maximum |
|---|---|---|---|
| CPU overhead | 1–2% | 3–5% | < 10% |
| Memory footprint | 80–120 MB | 150–200 MB | 300 MB |
| Disk I/O added | < 5 MB/hr | < 50 MB/hr | — |
| Network telemetry | 10–50 KB/hr/endpoint | 1 MB/hr/endpoint | — |
| Event throughput | 10,000 ev/s | 50,000 ev/s | — |
| Kernel event latency | < 1 ms | 2–5 ms | — |
| Process injection latency | < 10 ms | 20–50 ms | — |

**High Load** scenarios include: active software compilation, large file copy operations, high-frequency network scanning, or development workstations with many short-lived processes.

### Tuning Recommendations

#### Worker Thread Configuration

Increase `sysmon.workerThreads` on endpoints with sustained high event rates:

- Developer workstations: 2–4 threads
- Build servers / CI agents: 4–8 threads
- Servers with heavy network activity: 4–6 threads
- Standard office endpoints: 2 threads (default)

```json
"sysmon": {
  "workerThreads": 4
}
```

Monitor for dropped events with `edrcon dump --section sysmon | findstr dropped`. If drops are consistently above zero, increase thread count or add exclusions.

#### Queue Size Tuning

The `procmon.queueSize` controls the internal buffer between the kernel callback and the user-mode processing pipeline. Larger queues absorb short-duration spikes at the cost of memory:

- Default (10,000): suitable for most endpoints
- High-activity servers: 50,000–100,000
- Constrained environments (< 4 GB RAM): 2,000–5,000

#### File and Process Exclusions

Use path-based exclusions to reduce event volume from known-good, high-volume processes. Common exclusions for developer environments:

```json
"procmon": {
  "excludedPaths": [
    "C:\\Program Files\\Microsoft Visual Studio\\**\\VBCSCompiler.exe",
    "C:\\Program Files\\Git\\usr\\bin\\*.exe",
    "C:\\Users\\*\\AppData\\Local\\Programs\\cursor\\**"
  ]
}
```

Use wildcards sparingly. Over-exclusion creates detection blind spots.

#### Process Cache TTL

Reduce `dataProviders.processCache.ttlSec` on endpoints with very high process churn (e.g., build servers), and increase it on endpoints where processes are long-lived (e.g., servers):

- Build servers: 60–120 seconds
- Standard endpoints: 600 seconds (default)
- Servers with long-lived processes: 1800–3600 seconds

#### Cloud Upload Batch Tuning

Optimize batch settings based on network characteristics:

| Network Type | `batchSize` | `batchIntervalMs` |
|---|---|---|
| High-bandwidth LAN | 1000 | 2000 |
| WAN / VPN | 200 | 10000 |
| Intermittent / high-latency | 50 | 30000 |
| Air-gapped (offline buffer only) | — | — |

### Filter Tuning

#### PID-Based Whitelisting

For known-safe system services generating high event volume, temporary PID-based exclusion can be applied without a service restart using `edrcon`:

```cmd
REM Exclude a specific process temporarily (session only, not persisted)
edrcon process --exclude-pid 1234
```

Permanent exclusions should be placed in `procmon.excludedPaths`.

#### Event Type Filtering

To disable specific event types that are not relevant to your threat model (e.g., clipboard monitoring on air-gapped kiosks):

```json
"procmon": {
  "eventTimeouts": {
    "keyboardState": 0,
    "clipboardData": 0
  }
}
```

Setting a timeout to `0` disables that event type.

#### Path-Based Exclusions for File Events

High-volume directories such as browser caches, log directories, and temporary folders generate significant file system events. Exclude them when they are not relevant to your detection coverage:

```json
"filemon": {
  "excludedPaths": [
    "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\Microsoft\\Windows\\WER\\"
  ]
}
```

---

## Security Hardening

<picture>
  <source srcset="assets/Armor_defending_against_laser_beams_202605010255.avif" type="image/avif">
  <img src="assets/Armor_defending_against_laser_beams_202605010255.avif" alt="Self-Protection" width="100%">
</picture>

### Self-Protection Features

OpenArmor includes a multi-layered self-protection system that defends the EDR itself against tampering, disabling, and evasion by adversarial processes — including those running with local administrator privileges.

#### 1. Driver Protection

`edrdrv.sys` cannot be stopped or unloaded by any user-mode process, including those running as SYSTEM. Protection is implemented by:

- Registering a `PsSetLoadImageNotifyRoutine` callback that prevents `FltUnregisterFilter` from completing for `edrdrv.sys`.
- Elevating the driver's object security descriptor to deny `PROCESS_TERMINATE` from user mode.
- Using `ObRegisterCallbacks` to strip `LOAD_DRIVER` privileges from processes attempting to call `NtUnloadDriver` targeting `edrdrv.sys`.

To temporarily unload the driver for maintenance (e.g., during an upgrade), use `edrcon unprot` followed by a signed installer.

#### 2. Service Protection

Handle access to the `edrsvc.exe` process is restricted using `ObRegisterCallbacks`. Specifically:

- `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, and `PROCESS_INJECT_THREAD` rights are stripped from any process attempting to open a handle to `edrsvc.exe` unless the caller holds an allowlisted SID.
- This prevents adversarial tools from using `TerminateProcess`, `WriteProcessMemory`, or `CreateRemoteThread` against the EDR service.

#### 3. File Protection

EDR binary files (`edrsvc.exe`, `edrdrv.sys`, `edrpm.dll`, `edrcon.exe`, and configuration files in `C:\ProgramData\OpenArmor\`) are protected via the minifilter driver:

- Write, delete, and rename operations on protected paths are intercepted at the file system level.
- Operations from non-allowlisted processes are blocked with `STATUS_ACCESS_DENIED`.
- Allowlisting is based on the process image hash and code-signing certificate, not just the path.

#### 4. Registry Protection

Service and driver registry keys are protected using `CmRegisterCallback`:

- Keys under `HKLM\SYSTEM\CurrentControlSet\Services\OpenArmorEDR` and `HKLM\SYSTEM\CurrentControlSet\Services\OpenArmorEDRDrv` are protected.
- Write, delete, and rename operations are blocked for non-privileged processes.
- Attempts to modify the `ImagePath` value (a common persistence evasion technique) trigger an immediate alert.

#### 5. Anti-Tampering Detection

Independent of blocking, OpenArmor actively detects tampering attempts and generates high-severity alerts:

- Attempts to open high-privilege handles to `edrsvc.exe` or `edrdrv.sys` are logged even if blocked.
- Registry write attempts to protected keys generate `LLE_THREAT_ALERT` events with the `anti_tamper` policy match.
- Attempts to load drivers with names similar to OpenArmor components (homoglyph/typosquatting) are flagged.
- Periodic integrity checks on EDR binary hashes are performed; deviations generate alerts.

### Deployment Security

#### Network Segmentation

Restrict management traffic to a dedicated VLAN or security subnet:

- Endpoints should only be able to reach the management server and cloud backend endpoints.
- Block lateral movement by preventing endpoint-to-endpoint connections on management ports.
- Use a cloud proxy or API gateway to avoid exposing Elasticsearch directly to endpoints.

#### TLS Requirements

All cloud communication requires TLS 1.2 or higher. TLS 1.0 and 1.1 are disabled at compile time. Configure your backend to reject older TLS versions.

Recommended cipher suites (in preference order):

```
TLS_AES_256_GCM_SHA384 (TLS 1.3)
TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
TLS_AES_128_GCM_SHA256 (TLS 1.3)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
```

#### Certificate Pinning

For high-security environments, pin the cloud backend's TLS certificate leaf or intermediate CA:

```json
"cloud": {
  "http": {
    "pinnedCertFingerprint": "sha256//BASE64_ENCODED_CERT_FINGERPRINT="
  }
}
```

When pinning is enabled, connections to any endpoint presenting a different certificate are rejected, even if the certificate is otherwise valid.

#### Least-Privilege Service Account

The `edrsvc.exe` service runs as `LocalSystem` by default (required for kernel driver communication). Where possible:

- Restrict the service's network access using Windows Firewall rules scoped to specific destination IPs and ports.
- Use Group Policy to prevent the LocalSystem account from accessing network shares unnecessarily.
- Enable Windows Credential Guard to protect LSASS from the service process.

#### Policy Signing

Enable signature verification to prevent unauthorized policy modifications:

```json
"policy": {
  "signatureVerification": true,
  "signingCert": "C:\\ProgramData\\OpenArmor\\certs\\policy-signing.pem"
}
```

Sign policy files with your organization's code-signing certificate before deployment:

```cmd
edrcon compile --policy policy.json --output policy.signed.json --sign --cert policy-signing.pfx
```

#### Audit Logging

All administrative actions are recorded in a separate audit log (`C:\ProgramData\OpenArmor\logs\audit.log`):

- Policy changes (load, reload, signature verification result)
- Configuration changes
- `edrcon unprot` invocations (with operator identity)
- Enrollment and re-enrollment events
- Self-protection bypass events

### Driver Signing Requirements

#### Production Deployments

Production deployment of `edrdrv.sys` requires:

1. **Extended Validation (EV) Code Signing Certificate** from a trusted CA (DigiCert, Sectigo, GlobalSign, etc.)
2. **Microsoft Hardware Dev Center account** registered at https://partner.microsoft.com/dashboard
3. **WHQL Attestation Signing** — submit the driver package to the Hardware Dev Center for attestation signing

Steps for attestation signing:

```
1. Build edrdrv.sys in Release mode with /WX (warnings as errors)
2. Create a driver package (.cab or .hlkx)
3. Submit to Microsoft Hardware Dev Center portal
4. Microsoft signs the driver with a cross-certificate trusted by Secure Boot
5. Download signed driver package
6. Include signed edrdrv.sys in the installer
```

Attestation-signed drivers are accepted on all Windows 10/11 systems without disabling Secure Boot or test signing mode.

#### Development and Testing

For internal development and test environments:

```cmd
REM Enable test signing (requires restart)
bcdedit /set testsigning on

REM Sign driver with internal self-signed cert for testing
signtool sign /fd sha256 /v /a edrdrv.sys

REM Verify test signature
signtool verify /v /pa edrdrv.sys
```

Never use test-signed drivers in production. Test signing weakens the system's driver trust boundary.

---

## edrcon CLI Reference

`edrcon.exe` is the command-line management interface for OpenArmor. It communicates with the running `edrsvc` service via a local named pipe and can also be used to run the service in interactive mode.

### Global Options

```
edrcon [command] [options]

Global options:
  --config <path>     Path to edrsvc.json (default: auto-detect from registry)
  --service-pipe      Named pipe to connect to running service (default: auto)
  --timeout <ms>      Command timeout in milliseconds (default: 30000)
  --help              Show help for any command
  --version           Display edrcon version
```

### Command Reference

```
edrcon run [options]
  --config <path>       Path to edrsvc.json (default: auto-detect)
  --log-level <level>   Override configured log level for this session
  --service             Run as a Windows service (used by the service manager)
  --interactive         Run in foreground with console log output
  --no-selfprotect      Disable self-protection for this session (requires admin)

edrcon debug [options]
  --verbose             Maximum verbosity — all subsystems at trace level
  --policy-trace        Log policy evaluation result for every event
  --filter <type>       Only show events of specified LLE type (e.g., LLE_PROCESS_CREATE)
  --pid <pid>           Only show events from specified process ID
  --hostname <name>     Filter events by hostname (for multi-tenant debug sessions)
  --no-cloud            Suppress cloud upload during debug session
  --output <path>       Write debug events to file instead of console

edrcon dump [options]
  --format json|text    Output format (default: text)
  --section <name>      Subsection: all | cloud | policy | sysmon | procmon |
                        netmon | filemon | regmon | selfprotection | diagnostics
  --output <path>       Write dump to file

edrcon compile [options]
  --policy <path>       Policy JSON file to compile
  --output <path>       Write compiled (and optionally signed) policy to file
  --strict              Treat any policy warning as an error
  --test-events <path>  JSON file containing test events to run against compiled policy
  --sign                Sign the output policy (requires --cert)
  --cert <path>         PFX certificate file for policy signing
  --verify <path>       Verify an existing compiled policy signature

edrcon file [options]
  --hash <path>         Compute and display SHA256 and MD5 hashes of a file
  --verify <path>       Check Authenticode code signing status
  --verdict <path>      Query File Lookup Service (FLS) reputation for a file
  --submit <path>       Submit file to Valkyrie cloud sandbox for analysis
  --valkyrie-api <key>  Valkyrie API key (or set VALKYRIE_API_KEY env var)

edrcon process [options]
  --pid <pid>           Show enriched process information including ancestry chain
  --list                List all processes currently tracked in the process cache
  --injection-status    Show edrpm.dll injection status for all processes
  --exclude-pid <pid>   Temporarily exclude a PID from monitoring (session only)

edrcon rpcserver [options]
  --port <port>         RPC listen port (default: 11000)
  --bind <addr>         Bind address (default: 127.0.0.1)
  --auth-token <token>  Required token for RPC clients

edrcon unprot [options]
  --timeout <sec>       Duration of unprotected mode in seconds (default: 60)
  --reason <text>       Reason string recorded in audit log (required)
  --confirm             Required flag to confirm the operation

edrcon wait [options]
  --state <state>       Target state: running | stopped | ready | cloud-connected
  --timeout <sec>       Maximum wait time in seconds (default: 60)

edrcon enroll [options]
  --server <url>        Management server URL
  --token <token>       Enrollment token issued by management console
  --renew               Re-enroll an existing endpoint (rotates certificate)
  --endpoint-id <uuid>  Specify endpoint UUID (for migration from another system)
  --offline             Offline enrollment using a pre-provisioned identity bundle
  --bundle <path>       Path to offline identity bundle (.bundle file)

edrcon install [options]
  --config <path>       Configuration file to install
  --policy <path>       Policy file to install
  --certs <path>        Certificate directory to install
  --start               Start the service after installation

edrcon uninstall [options]
  --force               Force uninstallation even if service is running
  --purge               Remove all data including logs, buffer, and configuration
```

---

## Troubleshooting

### Common Issues

#### 1. Service Fails to Start — Driver Not Loaded

**Symptoms:** `edrsvc` reports `status: stopped` immediately after start; Windows Event Log shows error 1053.

**Root Cause:** `edrdrv.sys` failed to load, typically due to a code signing issue, missing kernel dependencies, or Secure Boot rejection.

**Diagnosis:**
```cmd
sc query OpenArmorEDRDrv
driverquery /FO LIST | findstr OpenArmor
type "C:\ProgramData\OpenArmor\logs\edrsvc.log" | findstr "driver"
Get-WinEvent -LogName System | Where-Object {$_.Message -match "edrdrv"} | Select-Object -First 10
```

**Fix:** Verify the driver is signed with an EV certificate and attestation-signed by Microsoft. In test environments, confirm test signing is enabled: `bcdedit /enum | findstr testsigning`.

---

#### 2. High CPU Usage — Event Storm

**Symptoms:** `edrsvc.exe` consuming > 20% CPU sustained; system feels sluggish.

**Root Cause:** A high-volume process (compiler, antivirus scan, large file copy) is generating more events than the worker threads can process.

**Diagnosis:**
```cmd
edrcon dump --section sysmon
edrcon process --list
```

**Fix:** Add the offending process to `procmon.excludedPaths` and increase `sysmon.workerThreads`. Restart the service.

---

#### 3. Missing Events — FltPort Buffer Overflow

**Symptoms:** `edrcon dump --section sysmon | findstr dropped` shows non-zero drop count.

**Root Cause:** The kernel-to-user-mode event buffer is saturating. Worker threads cannot drain the buffer fast enough.

**Diagnosis:**
```cmd
edrcon dump --section sysmon --format json | python -m json.tool
```

Look for `droppedEvents` > 0.

**Fix:** Increase `sysmon.workerThreads`, reduce event volume with exclusions, or increase `sysmon.bufferSizeMax`.

---

#### 4. Cloud Upload Failing — Credentials or Network

**Symptoms:** Events not appearing in Elasticsearch or Firehose; `lastHeartbeat` timestamp is stale.

**Diagnosis:**
```cmd
edrcon dump --section cloud | findstr "lastHeartbeat"
edrcon dump --section cloud | findstr "uploadErrors"
type "C:\ProgramData\OpenArmor\logs\edrsvc.log" | findstr "cloud"
```

**Fix:** Verify network connectivity to the cloud endpoint, check credentials in `edrsvc.json`, verify TLS certificate is trusted, and check that the Firehose stream or Elasticsearch index exists.

---

#### 5. Policy Not Loading — JSON Syntax Error

**Symptoms:** Service starts but generates no alerts; log shows `policy load failed`.

**Diagnosis:**
```cmd
edrcon compile --policy "C:\ProgramData\OpenArmor\policy.json" --strict
```

**Fix:** Correct any JSON syntax errors reported by `edrcon compile`. Re-deploy the fixed policy file.

---

#### 6. Process Injection Not Working — CIG Blocking

**Symptoms:** `edrcon process --injection-status` shows `not injected` for many processes.

**Root Cause:** Code Integrity Guard (CIG) or AppLocker is blocking injection of `edrpm.dll` into protected processes.

**Diagnosis:**
```cmd
edrcon dump --section procmon | findstr "injection"
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" | Select-Object -First 20
```

**Fix:** Add a CIG exception for `edrpm.dll` in the AppLocker/WDAC policy, or add the EDR publisher certificate to the WDAC allowlist.

---

#### 7. Self-Protection Preventing Admin Action

**Symptoms:** Administrator cannot delete or modify EDR files even from an elevated prompt.

**Root Cause:** `selfProtection.protectFiles` is blocking the operation (expected behavior).

**Fix:**
```cmd
REM Temporarily disable self-protection (60-second window)
edrcon unprot --timeout 120 --reason "Applying manual update" --confirm

REM Perform the administrative action within the window
copy newpolicy.json "C:\ProgramData\OpenArmor\policy.json"
```

---

#### 8. ELK Not Receiving Events — Elasticsearch Configuration

**Symptoms:** Index exists in Elasticsearch but is empty.

**Diagnosis:**
```cmd
edrcon dump --section cloud --format json
curl -u user:pass https://your-elk:9200/openarmor-*/_count
```

**Fix:** Verify the `openarmor_writer` role has `index` and `write` privileges on `openarmor-*`. Check that the index template is applied before the first event.

---

#### 9. Elasticsearch Disk Full — ILM Required

**Symptoms:** Elasticsearch nodes show red cluster health; new events not indexed.

**Root Cause:** No Index Lifecycle Management policy in place. Old indices growing without bound.

**Fix:** Apply the ILM policy from the ELK Configuration section. Delete the oldest indices manually if disk is critically full:

```bash
curl -X DELETE "https://your-elk:9200/openarmor-2024.01.*" -u admin:pass
```

---

#### 10. Kibana Dashboards Empty — Index Pattern

**Symptoms:** Kibana shows no data in OpenArmor dashboards.

**Fix:**
1. Navigate to Kibana > Stack Management > Index Patterns.
2. Create index pattern `openarmor-*`.
3. Set Time Field to `timestamp`.
4. Re-open dashboards. Adjust time range to match when data was ingested.

---

#### 11. Driver Installation Fails on Windows 11 — Secure Boot Enforcement

**Symptoms:** `edrdrv.sys` fails to load with `Code Integrity` error in Event Log.

**Root Cause:** Windows 11 24H2 and later enforce stricter driver signature requirements.

**Fix:** Ensure the driver is attestation-signed through the Microsoft Hardware Dev Center. Test-signed drivers require Secure Boot to be disabled.

---

#### 12. High Memory Usage — Process Cache Unbounded

**Symptoms:** `edrsvc.exe` memory usage growing over hours/days without bound.

**Diagnosis:**
```cmd
edrcon dump --section dataProviders --format json
```

**Fix:** Reduce `dataProviders.processCache.maxEntries` or `ttlSec`. Restart the service to clear the existing cache.

---

#### 13. No Network Events Generated

**Symptoms:** `LLE_NETWORK_CONNECT` events absent from telemetry.

**Root Cause:** `netmon.enabled` is `false`, or the Windows Filtering Platform (WFP) callout driver is not registered.

**Fix:** Enable `netmon` in `edrsvc.json`. Verify the WFP callout is registered:

```cmd
netsh wfp show filters
```

---

#### 14. edrcon Cannot Connect to Service

**Symptoms:** `edrcon dump` returns `error: cannot connect to edrsvc`.

**Root Cause:** Service is not running, or the named pipe is not accessible.

**Fix:**
```cmd
sc query OpenArmorEDR
sc start OpenArmorEDR
```

---

#### 15. Policy Changes Not Taking Effect

**Symptoms:** Updated policy file deployed, but behavior unchanged.

**Root Cause:** `policy.autoReload` is disabled, or the file was written to the wrong path.

**Fix:**
```cmd
REM Check loaded policy path
edrcon dump --section policy

REM Force reload
edrcon compile --policy policy.json --output "C:\ProgramData\OpenArmor\policy.json"
REM If autoReload is disabled, restart service
sc stop OpenArmorEDR && sc start OpenArmorEDR
```

---

#### 16. FLS Verdicts Always "Unknown"

**Symptoms:** All files show `flsVerdict: unknown` in events.

**Root Cause:** FLS endpoint is unreachable, or the FLS integration is disabled.

**Fix:**
```cmd
edrcon dump --section dataProviders | findstr fls
edrcon file --verdict "C:\Windows\System32\notepad.exe"
```

---

#### 17. Enrollment Fails — Token Expired

**Symptoms:** `edrcon enroll` returns `error: token invalid or expired`.

**Fix:** Generate a new enrollment token from the management console and re-run the enrollment command.

---

#### 18. Valkyrie Submission Fails

**Symptoms:** `edrcon file --submit` returns `error: unauthorized`.

**Fix:** Set the `VALKYRIE_API_KEY` environment variable or pass `--valkyrie-api` with a valid API key obtained from https://valkyrie.comodo.com.

---

#### 19. Service Crashes on Startup — Missing Runtime

**Symptoms:** Service starts then immediately terminates with exit code 0xC0000135.

**Root Cause:** Visual C++ 2019 or 2022 redistributable is not installed.

**Fix:** Install `vc_redist.x64.exe` from the OpenArmor installer package or from Microsoft's website.

---

#### 20. Log Files Not Rotating

**Symptoms:** Single log file growing beyond `maxSizeMb` limit.

**Root Cause:** File permissions prevent the service from creating new log files.

**Fix:** Ensure `SYSTEM` and `LOCAL SERVICE` have write access to `C:\ProgramData\OpenArmor\logs\`.

---

#### 21. Clipboard Events Causing Application Lag

**Symptoms:** Applications pause briefly when copying to clipboard.

**Root Cause:** `edrpm.dll` clipboard monitoring hook is running in the application's clipboard operation critical path.

**Fix:** Increase `procmon.eventTimeouts.clipboardData` or add high-frequency clipboard applications (e.g., password managers) to `procmon.excludedPaths`.

---

#### 22. No Events After Upgrade

**Symptoms:** Upgrade completed successfully, but telemetry stops flowing.

**Root Cause:** Old driver still loaded; new driver version mismatch.

**Fix:**
```cmd
edrcon unprot --timeout 120 --reason "Post-upgrade driver reload" --confirm
sc stop OpenArmorEDR
sc stop OpenArmorEDRDrv
sc start OpenArmorEDRDrv
sc start OpenArmorEDR
```

---

### Diagnostic Commands

```cmd
REM Full system diagnostic dump
edrcon dump --format json > "%TEMP%\openarmor_diagnostic.json"

REM Check driver status
sc query OpenArmorEDRDrv
driverquery /FO LIST | findstr OpenArmor

REM Check service status
sc query OpenArmorEDR

REM Check service logs for errors
type "C:\ProgramData\OpenArmor\logs\edrsvc.log" | findstr ERROR

REM Check event drop count
edrcon dump --section sysmon | findstr "dropped"

REM Check cloud connectivity
edrcon dump --section cloud | findstr "lastHeartbeat"

REM Check policy load status
edrcon dump --section policy

REM Test file hash and reputation
edrcon file --hash "C:\Windows\System32\notepad.exe"
edrcon file --verdict "C:\Windows\System32\notepad.exe"

REM List all monitored processes
edrcon process --list

REM Check injection status
edrcon process --injection-status

REM Verify policy syntax
edrcon compile --policy "C:\ProgramData\OpenArmor\policy.json" --strict

REM Check Windows Event Log for driver issues
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object {$_.Message -match "OpenArmor"} | Format-List

REM Check WFP for network monitoring
netsh wfp show filters > "%TEMP%\wfp_filters.txt"
```

### Log Reference

#### Log Locations

| Log File | Description |
|---|---|
| `C:\ProgramData\OpenArmor\logs\edrsvc.log` | Main service log — all subsystems |
| `C:\ProgramData\OpenArmor\logs\audit.log` | Administrative actions and policy changes |
| `C:\ProgramData\OpenArmor\logs\cloud.log` | Cloud upload operations (separate for high-volume debugging) |
| `C:\ProgramData\OpenArmor\crashes\` | Crash dump files (minidump format) |

#### Log Format

When `log.structured` is `true`, each line is a JSON object:

```json
{
  "ts": "2024-05-01T02:55:00.123Z",
  "level": "warn",
  "subsystem": "cloud",
  "msg": "Upload batch failed, will retry",
  "batchId": "uuid-v4",
  "attempt": 2,
  "errorCode": 503,
  "nextRetryMs": 2000
}
```

#### Log Rotation

Log files rotate when they reach `log.maxSizeMb`. Rotated files are renamed to `edrsvc.log.1`, `edrsvc.log.2`, etc. When `maxFiles` rotated files exist, the oldest is deleted.

#### Parsing with ELK

To parse structured OpenArmor logs in Logstash:

```ruby
filter {
  json { source => "message" target => "oa" }
  date { match => ["[oa][ts]", "ISO8601"] target => "@timestamp" }
  mutate { rename => { "[oa][level]" => "log.level" } }
}
```

---

## Screenshots

<picture>
  <source srcset="assets/Cybersecurity_analyst_dashboard_…_202605010256.avif" type="image/avif">
  <img src="assets/Cybersecurity_analyst_dashboard_…_202605010256.avif" alt="Analyst Dashboard" width="100%">
</picture>

### Platform Integration Screenshots

The following screenshots show OpenArmor integrated with the Comodo Dragon platform and demonstrate the full analyst workflow from alert triage to incident investigation.

**Detection & Alerting** — Real-time alert feed with severity classification, process information, MITRE ATT&CK technique tags, and FLS reputation verdicts. Analysts can filter by severity, endpoint, or technique and drill into any alert for full context.

![Detection and Alerting](assets/screenshots/Screenshot_1.avif)

**Event Details** — Full event context for any alert: enriched process chain showing the complete parent-child ancestry, file hash with FLS verdict, command line arguments, user context, and associated MITRE technique. Provides everything needed for triage without leaving the console.

![Event Details](assets/screenshots/Screenshot_2.avif)

**Main Dashboard** — SOC-level overview showing active alert counts by severity, trending threat techniques across the endpoint fleet, endpoint health status, cloud upload throughput, and top offending endpoints. Designed for display on a SOC monitor.

![Dashboard](assets/screenshots/Screenshot_3.avif)

**Process Timeline** — Chronological view of all events associated with a specific process across its lifetime, from creation through termination. Useful for reconstructing the full activity of a suspicious process.

![Process Timeline](assets/screenshots/Screenshot_4.avif)

**Process Tree View** — Hierarchical parent-child process visualization showing how a threat propagated through the process tree. Colors indicate event types (red: alerts, yellow: suspicious, grey: informational). Essential for understanding lateral movement and code execution chains.

![Process Tree View](assets/screenshots/Screenshot_5.avif)

**Event Search** — Full-text search across all telemetry with support for field-specific filters (`processName:powershell.exe AND severity:high`). Returns results in milliseconds from Elasticsearch. Supports export to JSON and CSV.

![Event Search](assets/screenshots/Screenshot_6.avif)

### ELK Stack Screenshots

The following screenshots show OpenArmor telemetry visualized in the open source Kibana interface.

![Elasticsearch UI 1](assets/screenshots/elastic%20ui1.avif)
![Elasticsearch UI 2](assets/screenshots/elastic%20ui2.avif)
![Elasticsearch UI 3](assets/screenshots/elastic%20ui3.avif)
![Elasticsearch UI 4](assets/screenshots/elastic%20ui4.avif)
![Elasticsearch UI 5](assets/screenshots/elastic%20ui5.avif)
![Elasticsearch UI 6](assets/screenshots/elastic%20ui6.avif)
![Elasticsearch UI 7](assets/screenshots/elastic%20ui7.avif)

---

## FAQ

**Q: Which versions of Windows does OpenArmor support?**
A: OpenArmor supports Windows 10 (1903 and later), Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022. Both x86-64 and ARM64 architectures are supported on Windows 11. Windows 7 and 8.1 are not supported due to kernel API requirements.

**Q: What is the performance impact on end-user machines?**
A: At default configuration, expect 1–2% additional CPU usage and 80–120 MB additional RAM. Most users will not notice any difference. On developer workstations with high process creation rates, it may be necessary to add exclusions for build tools to keep overhead in the 2–5% range.

**Q: How quickly are threats detected?**
A: Detection latency from event occurrence to alert generation is typically under 100 milliseconds on the endpoint. Cloud visibility latency (time from event to alert appearing in the cloud console) depends on batch interval settings — typically 3–10 seconds with default configuration.

**Q: Can I write my own detection rules?**
A: Yes. OpenArmor's policy engine uses a JSON-based rule language that supports field matching, logical operators, threshold conditions, and sequence detection. Rules are compiled with `edrcon compile` and hot-reloaded. See the [Policy Reference](getting-started/policy-reference.md) for the full rule language specification.

**Q: Does OpenArmor work in air-gapped environments?**
A: Yes. Disable cloud providers in `edrsvc.json` and set `offlineBufferMaxMb` to accommodate the expected event volume between data transfers. Use `edrcon dump` to export events to JSON for manual transfer to your analysis platform. Enrollment can use offline bundle mode.

**Q: Does OpenArmor comply with GDPR?**
A: OpenArmor collects process telemetry including command-line arguments, which may contain user-entered data. Operators are responsible for ensuring their deployment complies with applicable privacy regulations. OpenArmor does not transmit data outside the configured cloud backend. Command-line capture can be disabled by setting `procmon.captureCmdLine: false` in `edrsvc.json`.

**Q: Does OpenArmor conflict with Windows Defender / Microsoft Defender for Endpoint?**
A: OpenArmor and Windows Defender Antivirus can run simultaneously — they operate at different layers. However, running OpenArmor alongside Microsoft Defender for Endpoint (MDE) is not recommended in production as both tools use WFP, minifilter, and kernel callbacks, which may cause performance issues or event duplication. Choose one or the other for comprehensive EDR coverage.

**Q: What is the false positive rate?**
A: The default policy is tuned for low false-positive rates. Out-of-the-box, most environments see fewer than 5 alerts per day per 100 endpoints that require analyst review. False positive rates depend heavily on your environment — custom software, unusual admin tools, and developer workstations typically require policy tuning.

**Q: How do I upgrade OpenArmor to a new version?**
A: Download the new installer from the GitHub Releases page. Run `edrcon unprot --timeout 300 --reason "Upgrade" --confirm` to temporarily disable self-protection, then execute the installer. The installer will stop services, replace binaries, run `sc` commands to update service configuration, and restart services. No data or configuration is lost during an upgrade.

**Q: Is commercial support available?**
A: Yes. Comodo Security Solutions offers commercial support, managed detection and response (MDR), and professional services for enterprise OpenArmor deployments. Contact enterprise@openedr.com for pricing and SLA options.

**Q: How does OpenArmor compare to Wazuh?**
A: Wazuh is primarily a log-based HIDS/SIEM agent; its endpoint telemetry comes from Windows Event Log and Sysmon. OpenArmor provides kernel-level visibility with a custom driver, giving lower-latency and richer context (e.g., process injection detection, clipboard monitoring, FLS reputation). Wazuh has a broader SIEM integration ecosystem; OpenArmor has deeper endpoint behavioral detection.

**Q: How does OpenArmor compare to Velociraptor?**
A: Velociraptor is primarily a digital forensics and incident response (DFIR) tool designed for on-demand investigation. OpenArmor is a continuous monitoring EDR — it generates telemetry 24/7 and applies detection policies in real time. The two tools are complementary; some organizations run both.

**Q: How does OpenArmor compare to OSQuery?**
A: OSQuery is a query-based endpoint visibility tool; you ask questions and get point-in-time answers. OpenArmor streams events continuously and applies real-time detection rules. OSQuery has no alerting layer; OpenArmor does. OSQuery supports multi-platform natively; OpenArmor currently focuses on Windows.

**Q: Can OpenArmor detect ransomware?**
A: Yes. The default policy includes rules targeting ransomware behaviors: mass file modification with entropy changes, shadow copy deletion (`vssadmin delete shadows`), and encryption extension patterns. OpenArmor can detect ransomware activity within seconds of onset and generate high-severity alerts.

**Q: Does OpenArmor perform automated response actions?**
A: In the current release, OpenArmor generates alerts and telemetry but does not automatically terminate processes or block network connections. Automated response is on the roadmap for v3.1. Integration with external SOAR platforms via the HTTP REST backend can be used to trigger response actions based on OpenArmor alerts.

**Q: What happens if the cloud backend goes offline?**
A: Events are buffered locally in the offline buffer (up to `offlineBufferMaxMb`, default 500 MB). Detection rules continue to run on the endpoint. When the backend reconnects, buffered events are uploaded in order. No events are lost unless the buffer fills.

**Q: Can I run multiple OpenArmor instances on the same machine?**
A: No. Only one instance of `edrdrv.sys` can be loaded at a time. Installing OpenArmor over an existing installation requires uninstalling the old version first.

**Q: Is the kernel driver open source?**
A: Yes. The complete source code for `edrdrv.sys`, `edrsvc.exe`, `edrpm.dll`, and `edrcon.exe` is available in this repository under the MIT License. You are free to audit, modify, and build from source.

**Q: How do I report a security vulnerability in OpenArmor?**
A: Please do not open public GitHub issues for security vulnerabilities. Email security@openedr.com with a description of the vulnerability. We follow a 90-day responsible disclosure policy and will acknowledge receipt within 48 hours.

**Q: What events does OpenArmor NOT collect?**
A: By default, OpenArmor does not collect audio/video streams, browser history, email content, or screen captures. These capabilities are outside the scope of the EDR and would raise significant privacy concerns. Network packet capture (full PCAP) is also not performed — only connection metadata is collected.

**Q: Can OpenArmor monitor virtual machines from the host?**
A: No. OpenArmor runs as a driver inside each monitored OS instance. Hypervisor-level visibility would require a separate solution (e.g., VMware vSphere Trust Authority or similar).

**Q: How do I customize the Kibana dashboards?**
A: Import the provided dashboard JSON from `getting-started/kibana-dashboards.ndjson` into Kibana (Stack Management > Saved Objects > Import). Dashboards can then be customized in the Kibana interface and exported for version control.

**Q: How many endpoints can one ELK cluster handle?**
A: A well-tuned ELK cluster (3 nodes, 32 GB RAM each, SSD storage) can handle approximately 5,000–10,000 endpoints generating typical event volumes. For larger deployments, use Elasticsearch's hot-warm-cold architecture, cross-cluster replication, or consider the AWS OpenSearch managed service.

---

## Roadmap

OpenArmor follows a community-driven roadmap. The following features are planned based on contributor and enterprise feedback. Dates are targets, not guarantees.

| Version | Target | Features |
|---|---|---|
| **v2.6** | Q3 2024 | Linux agent (eBPF-based), improved Windows installer UX, ILM policy wizard for ELK, Azure Event Hubs backend (beta) |
| **v2.7** | Q4 2024 | ARM64 driver signing, macOS proof-of-concept agent (endpoint syscall), REST API for event query, improved policy rule language (regex support) |
| **v3.0** | Q2 2025 | Full macOS support (Endpoint Security framework), GraphQL API for telemetry query, web-based management console (open source), GCP Pub/Sub backend (GA) |
| **v3.1** | Q4 2025 | ML-based behavioral anomaly detection (local inference, ONNX models), automated response actions (process isolation, network block), SOAR webhook integration |
| **v3.2** | Q2 2026 | Multi-platform unified management console, threat intelligence feed integration (MISP, OpenCTI), deception-based detection (honeypot file monitoring) |
| **Long-term** | 2026+ | Container/Kubernetes workload visibility, hardware-based attestation (TPM), real-time threat hunting query language, federated multi-tenant architecture |

Community contributions toward any roadmap item are welcome. If you are working on a major feature, please open a GitHub issue first to discuss the approach and avoid duplicating effort.

---

## Contributing

<picture>
  <source srcset="assets/Diverse_developers_collaborating…_202605010255.avif" type="image/avif">
  <img src="assets/Diverse_developers_collaborating…_202605010255.avif" alt="Community" width="100%">
</picture>

OpenArmor is built by the community and welcomes contributions of all kinds. Whether you are fixing a typo in the docs, submitting a detection rule, or porting the driver to a new platform, your contribution is valued.

For the full contributing guide, see [CONTRIBUTING.md](CONTRIBUTING.md).

### Development Environment Setup

1. **Prerequisites:**
   - Windows 10/11 or Windows Server 2019/2022 (for driver development)
   - Visual Studio 2019 or 2022 with Desktop C++ and Windows Driver Kit (WDK) workloads
   - Windows Driver Kit (WDK) 10.0.19041 or later — must match your target OS build
   - Windows SDK 10.0.19041 or later
   - CMake 3.20 or later (for external project builds)
   - Git for Windows

2. **Clone the repository:**
   ```cmd
   git clone https://github.com/openarmor/openarmor.git
   cd openarmor\edrav2
   ```

3. **Open the solution:**
   - Visual Studio 2022: open `build\vs2022\edrav2.sln`
   - Visual Studio 2019: open `build\vs2019\edrav2.sln`

4. **Build in Debug mode:**
   - Select the `Debug | x64` configuration
   - Build All (`Ctrl+Shift+B`)
   - Outputs land in `build\bin\x64\Debug\`

5. **Enable test signing for local driver development:**
   ```cmd
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

6. **Deploy for local testing:**
   ```cmd
   cd build\bin\x64\Debug
   install_dev.cmd
   edrcon run --interactive --log-level debug
   ```

### Code Style

OpenArmor follows these C++ conventions:

- **Standard:** C++17 minimum
- **Naming:** `camelCase` for variables and functions, `PascalCase` for classes and types, `UPPER_SNAKE_CASE` for constants and macros
- **Namespaces:** All OpenArmor code lives in the `openarmor::` namespace hierarchy
- **Headers:** `.h` extension; no using-directives in headers
- **Comments:** Doxygen-style `///` for public APIs
- **Error handling:** Use `LOGLEVEL(...)` macros; avoid throwing exceptions in hot paths
- **Memory:** Use RAII and smart pointers (`std::unique_ptr`, `std::shared_ptr`); no raw `new`/`delete` outside constructors
- **Kernel code:** Follow Windows kernel coding conventions; use `ExAllocatePool2` (not the deprecated `ExAllocatePool`); check all return values

Run clang-format with the provided `.clang-format` before submitting:
```cmd
clang-format -i -style=file src\**\*.cpp src\**\*.h
```

### Writing and Submitting a Detection Rule

Detection rules are the highest-impact contribution for most users. To write a rule:

1. Identify the behavior you want to detect (MITRE technique, specific malware TTP, etc.)
2. Write the rule in JSON following the rule language specification in [getting-started/policy-reference.md](getting-started/policy-reference.md)
3. Test with synthetic events: `edrcon compile --policy my_rule.json --test-events tests/test_events.json`
4. Verify the rule has no false positives in your environment by running it in `audit` mode for at least one week
5. Submit via pull request with:
   - The rule JSON in `rules/contributed/`
   - Test events in `tests/rules/`
   - A description of the detected behavior, MITRE technique ID, and known false-positive scenarios

### Submitting a Bug Report

Before submitting a bug report:
1. Check [existing issues](https://github.com/openarmor/openarmor/issues) to avoid duplicates
2. Collect a diagnostic dump: `edrcon dump --format json > diagnostic.json`
3. Collect relevant log lines from `edrsvc.log`
4. Note the OpenArmor version (`edrcon --version`), Windows version, and any third-party security software installed

Use the [Bug Report template](https://github.com/openarmor/openarmor/issues/new?template=bug_report.md) and attach the diagnostic dump.

### Submitting a Pull Request

1. Fork the repository and create a feature branch: `git checkout -b feature/my-improvement`
2. Make your changes with appropriate tests
3. Ensure all existing tests pass: open `edrav2-tests.sln` and run all tests
4. Verify your code compiles in both Debug and Release configurations
5. Submit the PR against the `main` branch
6. Fill in the PR template completely — incomplete templates delay review
7. A maintainer will review within 5 business days and provide feedback

### Testing Requirements

- All new functionality must include unit tests using [Catch2](https://github.com/catchorg/Catch2)
- Test files live in `src/tests/` alongside the code they test
- Integration tests that require a running service are in `tests/integration/`
- Run the full test suite before submitting: build and run `edrav2-tests` project
- New detection rules must include at least one true-positive test event and one true-negative test event in JSON format

### Kernel Driver Signing for Development

For development builds, use test signing as described above. If you need to share a test build with others on separate machines, you can create a self-signed certificate:

```cmd
REM Create self-signed cert
makecert -r -pe -ss PrivateCertStore -n "CN=OpenArmor Dev" OpenArmorDev.cer

REM Sign the driver
signtool sign /v /s PrivateCertStore /n "OpenArmor Dev" /fd sha256 edrdrv.sys

REM Install cert on target machine
certutil -addstore TrustedPublisher OpenArmorDev.cer
certutil -addstore Root OpenArmorDev.cer
```

### Review Process and SLA

- **Bug fixes:** First review within 5 business days; merge within 2 weeks if approved
- **New features:** Initial feedback within 10 business days; may require RFC discussion for large changes
- **Detection rules:** Review within 5 business days; requires 1 maintainer approval and passing CI
- **Documentation:** First review within 5 business days; typically fast to merge

All contributions must pass CI (GitHub Actions: build, unit tests, clang-format check) before merging.

### Types of Contributions

The following contribution types are most needed by the project:

| Contribution Type | Priority | Skill Required |
|---|---|---|
| Detection rules | **Critical** | Security knowledge, JSON |
| Bug fixes | **High** | C++, Windows internals |
| Documentation improvements | **High** | Technical writing |
| Platform ports (Linux, macOS) | **High** | Kernel development |
| Performance improvements | **Medium** | C++ profiling, Windows driver |
| New cloud backend integrations | **Medium** | C++, cloud provider APIs |
| UI / web console | **Medium** | React, TypeScript |
| Test coverage improvements | **Medium** | C++, Catch2 |

---

## Community & Support

We believe that endpoint security should be transparent, auditable, and accessible to every organization — regardless of size or budget. OpenArmor is built by a global community of security engineers, incident responders, and researchers.

| Channel | Purpose | Link |
|---|---|---|
| Slack | Real-time discussion, quick questions, community | https://openedr.com/register/ |
| Community Forums | Long-form discussion, architecture questions, showcases | https://community.openedr.com/ |
| GitHub Issues | Bug reports, feature requests | https://github.com/openarmor/openarmor/issues |
| GitHub Discussions | RFCs, roadmap discussion, general questions | https://github.com/openarmor/openarmor/discussions |
| General Email | Registration, general inquiries | register@openedr.com |
| Commercial Support | Enterprise SLA, professional services, MDR | enterprise@openedr.com |
| Security Disclosures | Responsible vulnerability disclosure | security@openedr.com |

Please do not email security@openedr.com for general support questions. Use GitHub Issues or the community forums instead.

---

## License

OpenArmor is released under the [MIT License](LICENSE.md).

```
MIT License

Copyright (c) 2020-2024 OpenArmor Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Third-Party Licenses

OpenArmor incorporates the following open source components. Their licenses are reproduced in the `THIRD_PARTY_LICENSES/` directory and summarized here:

| Component | Version | License | Purpose |
|---|---|---|---|
| Boost | 1.83.0 | BSL-1.0 | STL extensions, Boost.Asio for async I/O |
| OpenSSL | 3.1.x | Apache 2.0 / OpenSSL License | TLS, cryptographic primitives |
| gRPC | 1.60.x | Apache 2.0 | Management plane RPC communication |
| AWS SDK for C++ | 1.11.x | Apache 2.0 | Kinesis Firehose integration |
| Microsoft Detours | 4.0.1 | MIT | API hooking for process injection |
| log4cplus | 2.1.x | Apache 2.0 | Structured logging framework |
| Catch2 | 3.5.x | BSL-1.0 | C++ unit testing framework |
| Google Crashpad | HEAD | Apache 2.0 | Crash reporting and minidump generation |
| nlohmann/json | 3.11.x | MIT | JSON parsing and serialization |
| cpp-httplib | 0.14.x | MIT | HTTP client for cloud backends |
| libcurl | 8.5.x | curl License (MIT-like) | HTTP/HTTPS transport layer |
| zlib | 1.3.x | zlib License | Compression for cloud payloads |

Full license texts are available in `THIRD_PARTY_LICENSES/`. The Boost Software License 1.0 and the Apache License 2.0 are permissive licenses that allow use in commercial products. There are no GPL-licensed components — OpenArmor can be freely incorporated into proprietary software.

---

## Closing

<div align="center">

<picture>
  <source srcset="assets/Cybersecurity_shield_logo_OpenArmor_202605010313.avif" type="image/avif">
  <img src="assets/Cybersecurity_shield_logo_OpenArmor_202605010313.avif" alt="OpenArmor" width="200">
</picture>

**OpenArmor** — Open Source Endpoint Detection & Response

*Built by the community. Securing the world.*

[GitHub](https://github.com/openarmor/openarmor) • [Slack](https://openedr.com/register/) • [Docs](getting-started/) • [Issues](https://github.com/openarmor/openarmor/issues)

</div>
