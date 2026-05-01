# Installation Instructions

OpenArmor is an open source Windows Endpoint Detection and Response (EDR) agent. It installs a lightweight kernel driver and user-space service that monitor security-relevant activity across a Windows endpoint, generating structured telemetry that can be forwarded to any SIEM or log analysis platform.

## What OpenArmor Installs

| Component | Path | Role |
|---|---|---|
| `edrsvc.exe` | `C:\Program Files\OpenArmor\edrsvc.exe` | Windows service, core agent process |
| `edrdrv.sys` | `C:\Program Files\OpenArmor\edrdrv.sys` | Kernel driver, captures OS-level events |
| `edrpm.dll` | `C:\Program Files\OpenArmor\edrpm.dll` | Injected DLL for user-space API interception |
| `edrcon.exe` | `C:\Program Files\OpenArmor\edrcon.exe` | Command-line control and diagnostic utility |

OpenArmor monitors:

- Process creation and termination (with full command-line capture)
- Network connections (TCP/UDP, DNS queries)
- File system activity (create, write, delete, rename)
- Registry modifications
- DLL/module load events
- Driver load events
- Thread injection and cross-process memory operations
- Windows Management Instrumentation (WMI) activity
- Scheduled task creation and modification

Telemetry is written as newline-delimited JSON to `C:\ProgramData\edrsvc\log\output_events\` by default. File reputation lookups are performed against [Comodo Valkyrie](https://valkyrie.comodo.com/) and Comodo File Lookup Service (FLS) at `fls.security.comodo.com`.

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Operating System | Windows 10 version 1903 (18362) | Windows 11 / Server 2022 |
| Architecture | x64 only | x64 |
| RAM | 4 GB | 8 GB |
| Disk space | 2 GB (installation + log headroom) | 10 GB |
| .NET Framework | 4.7.2 | 4.8 |
| Privileges | Local Administrator | Domain Administrator |

**Supported operating systems:**

- Windows 10 (version 1903 and later), all editions
- Windows 11 (all editions)
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

**Network requirements:**

- Outbound HTTPS (TCP 443) to cloud backend services
- Outbound access to `valkyrie.comodo.com` (file reputation)
- Outbound access to `fls.security.comodo.com` (file lookup service)
- No inbound ports required

**Driver requirements:**

- Secure Boot must allow third-party kernel drivers (or be configured to trust the OpenArmor signing certificate)
- Windows Driver Signature Enforcement must be enabled (production) or test signing mode enabled (development/test builds)

---

## Quick Start

There are three ways to get OpenArmor running. Choose the path that fits your environment.

### Path A — MSI Installer (Recommended)

Best for: individual endpoints, evaluations, and production deployments.

1. Download `OpenArmor-Setup-x64.msi` from [Releases](https://github.com/openarmor/openarmor/releases)
2. Run the installer as Administrator
3. Point Filebeat (or any log shipper) at `C:\ProgramData\edrsvc\log\output_events\`

Full details: [MSI Installation](#msi-installation)

### Path B — Docker Backend + MSI Agent

Best for: teams who want a ready-made ELK stack for viewing telemetry alongside the agent.

1. Stand up the Docker Compose stack (Elasticsearch, Logstash, Kibana) on your analysis host
2. Install the MSI on each monitored endpoint
3. Configure Filebeat on each endpoint to ship to your Logstash/Elasticsearch instance

Full details: [Docker Installation](DockerInstallation.md)

### Path C — Build from Source + Manual Install

Best for: developers, security researchers, or environments requiring custom builds.

1. Clone the repository and build with Visual Studio 2019 + WDK
2. Sign `edrdrv.sys` with a valid code-signing certificate
3. Copy binaries to `C:\Program Files\OpenArmor\` and register the service

Full details: [Build Instructions](BuildInstructions.md)

---

## MSI Installation

### Step 1 — Download the Installer

Download the latest `OpenArmor-Setup-x64.msi` from:

```
https://github.com/openarmor/openarmor/releases
```

Verify the file hash against the checksum published on the release page before proceeding.

### Step 2 — Run the Installer (GUI)

1. Right-click `OpenArmor-Setup-x64.msi` and select **Run as administrator**.
2. On the Welcome screen, click **Next**.
3. Accept the license agreement and click **Next**.
4. Choose the installation folder (default: `C:\Program Files\OpenArmor`) and click **Next**.
5. Click **Install**. Windows may display a User Account Control (UAC) prompt — click **Yes**.
6. The installer registers `OpenArmorEDR` as a Windows service, installs the kernel driver `edrdrv.sys`, and starts the service automatically.
7. Click **Finish**.

> **Note:** The installer requires Administrator privileges. If you do not see the UAC prompt, right-click the MSI and select "Run as administrator" explicitly.

### Step 3 — Silent / Unattended Installation

For automated deployment via Group Policy, SCCM, Intune, or other management tools:

```cmd
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart
```

Silent install with a custom installation directory:

```cmd
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart INSTALLDIR="C:\Program Files\OpenArmor"
```

Silent install with verbose logging for troubleshooting:

```cmd
msiexec /i OpenArmor-Setup-x64.msi /quiet /norestart /l*v "%TEMP%\openarmor_install.log"
```

### Step 4 — Verify the Installation

Open an elevated PowerShell or Command Prompt and run:

```powershell
# Check the user-space service
sc query OpenArmorEDR

# Check the kernel driver service
sc query OpenArmorEDRDrv

# Dump current agent status and configuration
edrcon dump
```

Expected output for a healthy installation:

```
SERVICE_NAME: OpenArmorEDR
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Default Installation Paths

| Item | Default Path |
|---|---|
| Service binary | `C:\Program Files\OpenArmor\edrsvc.exe` |
| Kernel driver | `C:\Program Files\OpenArmor\edrdrv.sys` |
| Injected DLL | `C:\Program Files\OpenArmor\edrpm.dll` |
| Control utility | `C:\Program Files\OpenArmor\edrcon.exe` |
| Configuration file | `C:\Program Files\OpenArmor\edrsvc.json` |
| Log directory | `C:\ProgramData\edrsvc\log\` |
| Telemetry output | `C:\ProgramData\edrsvc\log\output_events\` |
| Crash dumps | `C:\ProgramData\edrsvc\crashpad\` |

---

## Configuration

The agent reads its configuration from:

```
C:\Program Files\OpenArmor\edrsvc.json
```

Changes to this file require a service restart to take effect:

```powershell
Restart-Service OpenArmorEDR
```

### Key Configuration Settings

| Setting | Type | Description |
|---|---|---|
| `logLevel` | string | Logging verbosity: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `outputPath` | string | Directory where telemetry JSON files are written |
| `cloudBackend.endpoint` | string | URL of a remote policy/verdict backend (optional) |
| `policy.path` | string | Path to the alerting policy file |
| `fileReputation.enabled` | boolean | Enable/disable Comodo FLS file reputation lookups |
| `fileReputation.flsServer` | string | FLS server hostname (default: `fls.security.comodo.com`) |
| `fileReputation.valkyrieUrl` | string | Valkyrie URL (default: `https://valkyrie.comodo.com`) |

### Minimal Working Configuration

```json
{
  "logLevel": "info",
  "outputPath": "C:\\ProgramData\\edrsvc\\log\\output_events\\",
  "policy": {
    "path": "C:\\Program Files\\OpenArmor\\policy.json",
    "enabled": true
  },
  "fileReputation": {
    "enabled": true,
    "flsServer": "fls.security.comodo.com",
    "valkyrieUrl": "https://valkyrie.comodo.com"
  },
  "cloudBackend": {
    "enabled": false,
    "endpoint": ""
  }
}
```

> **Tip:** After editing `edrsvc.json`, run `edrcon check-config` to validate the file before restarting the service.

---

## Telemetry Output

### Output Location

All telemetry events are written to:

```
C:\ProgramData\edrsvc\log\output_events\
```

Files are rotated automatically. Each file contains newline-delimited JSON, with one event object per line (NDJSON format). This is compatible with Filebeat, Logstash, Fluentd, and most modern log shippers out of the box.

### Example Event

```json
{
  "baseType": "LGW_PROCESS_CREATE",
  "baseTime": "2024-03-15T10:23:45.123Z",
  "pid": 4812,
  "ppid": 1234,
  "imagePath": "C:\\Windows\\System32\\cmd.exe",
  "cmdLine": "cmd.exe /c whoami",
  "userName": "DOMAIN\\user",
  "sessionId": 1,
  "integrityLevel": "Medium",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Forwarding to Filebeat

Filebeat is the recommended log shipper for forwarding OpenArmor telemetry to Elasticsearch. Configure a `filestream` input pointing at the output directory:

See the step-by-step Filebeat configuration guide: [Setting up OpenArmor and Filebeat](SettingFileBeat.md)

### Forwarding to AWS Firehose

To ship events directly to an AWS Kinesis Firehose delivery stream:

1. Configure the Firehose delivery stream in your AWS account with an S3 or Elasticsearch destination.
2. Deploy the Kinesis Agent for Windows on the endpoint, or use a Firehose-compatible log agent.
3. Point the agent at `C:\ProgramData\edrsvc\log\output_events\*.json`.
4. The NDJSON format is natively compatible with Firehose record boundaries.

Alternatively, configure the OpenArmor cloud backend to point at an AWS Gateway endpoint that proxies to Firehose.

---

## Uninstallation

### Via Control Panel

1. Open **Settings** > **Apps** > **Installed apps** (Windows 11) or **Control Panel** > **Programs** > **Programs and Features** (Windows 10).
2. Locate **OpenArmor EDR** in the list.
3. Click **Uninstall** and follow the prompts.

### Silent Uninstall

```cmd
msiexec /x OpenArmor-Setup-x64.msi /quiet /norestart
```

If you no longer have the original MSI, uninstall using the product code:

```cmd
# Find the product code first
wmic product where "Name like 'OpenArmor%'" get IdentifyingNumber,Name

# Then uninstall using the product code
msiexec /x {PRODUCT-CODE-GUID} /quiet /norestart
```

### Manual Cleanup

If the MSI uninstaller fails or for forensic cleanup, remove components manually:

```cmd
# Stop and delete the user-space service
sc stop OpenArmorEDR
sc delete OpenArmorEDR

# Stop and delete the kernel driver service
sc stop OpenArmorEDRDrv
sc delete OpenArmorEDRDrv

# Remove the installation directory
rmdir /s /q "C:\Program Files\OpenArmor"

# Remove the data directory (contains logs — back up first if needed)
rmdir /s /q "C:\ProgramData\edrsvc"

# Remove registry keys
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\OpenArmorEDR" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\OpenArmorEDRDrv" /f
reg delete "HKLM\SOFTWARE\OpenArmor" /f
```

> **Note:** A reboot may be required to fully unload the kernel driver `edrdrv.sys` if it was running at the time of uninstallation.

---

## Upgrading

OpenArmor upgrades are performed by installing the new MSI over the existing installation. The installer preserves configuration files.

### Standard Upgrade Procedure

```powershell
# 1. Stop the service gracefully
Stop-Service OpenArmorEDR -Force

# 2. Install the new MSI (the installer will handle the in-place upgrade)
msiexec /i OpenArmor-Setup-x64-NEW.msi /quiet /norestart

# 3. Verify the new version
edrcon version

# 4. Start the service (if not started automatically)
Start-Service OpenArmorEDR
```

### What Is Preserved During Upgrade

| Item | Preserved? |
|---|---|
| `edrsvc.json` (configuration) | Yes |
| `policy.json` (alerting policy) | Yes |
| Telemetry log files in `output_events\` | Yes |
| Service registration | Updated automatically |
| Kernel driver | Replaced by new version |

> **Important:** Always read the release notes for a new version before upgrading. Some releases require configuration schema changes.

---

## Troubleshooting

### Service Fails to Start

**Symptom:** `sc query OpenArmorEDR` shows `STOPPED` and attempts to start fail.

**Steps:**

1. Check the Windows Event Log:
   ```powershell
   Get-WinEvent -LogName System | Where-Object { $_.ProviderName -eq "Service Control Manager" -and $_.Message -like "*OpenArmor*" } | Select-Object -First 10
   ```

2. Check for driver signing errors:
   ```cmd
   # View code integrity log
   Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" | Select-Object -First 20
   ```

3. Verify driver signature:
   ```cmd
   signtool verify /pa /v "C:\Program Files\OpenArmor\edrdrv.sys"
   ```

4. If running a development build, ensure test signing mode is enabled:
   ```cmd
   bcdedit /enum | findstr testsigning
   ```

### No Events Appearing in Output Directory

**Symptom:** `C:\ProgramData\edrsvc\log\output_events\` is empty or not being updated.

**Steps:**

1. Confirm the service is running:
   ```powershell
   Get-Service OpenArmorEDR | Select-Object Status
   ```

2. Check that the output directory exists and is writable:
   ```powershell
   Test-Path "C:\ProgramData\edrsvc\log\output_events"
   icacls "C:\ProgramData\edrsvc\log\output_events"
   ```

3. Check available disk space:
   ```powershell
   Get-PSDrive C | Select-Object Used,Free
   ```

4. Review the agent's own log for errors:
   ```
   C:\ProgramData\edrsvc\log\edrsvc.log
   ```

### High CPU Usage

**Symptom:** `edrsvc.exe` consumes excessive CPU over a sustained period.

**Steps:**

1. Identify which event types are generating high volume using `edrcon dump`.
2. Add exclusions for noisy paths in `edrsvc.json`:
   ```json
   "filters": {
     "excludePaths": [
       "C:\\Windows\\SoftwareDistribution\\",
       "C:\\Program Files\\YourAVProduct\\"
     ]
   }
   ```
3. Adjust `logLevel` to `"warn"` or `"error"` to reduce log I/O overhead.
4. Restart the service after configuration changes.

### Kernel Driver Not Loading

**Symptom:** `sc query OpenArmorEDRDrv` shows `STOPPED` or the driver fails to load at boot.

**Steps:**

1. Verify Secure Boot settings allow the driver's signing certificate.
2. Confirm the driver binary is present and not corrupted:
   ```powershell
   Get-FileHash "C:\Program Files\OpenArmor\edrdrv.sys" -Algorithm SHA256
   ```
3. Check the System event log for error code `0xC0000428` (invalid image hash) or `0x0000007E` (driver load failure).

### Useful Diagnostic Commands

```powershell
# Full agent status dump
edrcon dump

# Show current version
edrcon version

# Validate configuration file
edrcon check-config

# Show driver and service status
sc query OpenArmorEDR
sc query OpenArmorEDRDrv

# Show recent service events from Event Log
Get-WinEvent -LogName Application -MaxEvents 50 | Where-Object { $_.Message -like "*edr*" }

# Check driver signing status
signtool verify /pa "C:\Program Files\OpenArmor\edrdrv.sys"
```

---

## Next Steps

After installation and verification, explore the rest of the documentation:

| Guide | Description |
|---|---|
| [Build Instructions](BuildInstructions.md) | Compile OpenArmor from source using Visual Studio and WDK |
| [Docker Installation](DockerInstallation.md) | Stand up the Elasticsearch + Logstash + Kibana backend with Docker Compose |
| [Setting up Elasticsearch, Kibana, and Logstash](SettingELK.md) | Configure the ELK stack to receive and index OpenArmor telemetry |
| [Setting up OpenArmor and Filebeat](SettingFileBeat.md) | Configure Filebeat to ship telemetry from the endpoint to your ELK stack |
| [Editing Alerting Policies](EditingAlertingPolicies.md) | Customize detection rules and alerting thresholds |
| [Setting up Kibana](SettingKibana.md) | Build dashboards and saved searches for OpenArmor telemetry in Kibana |
