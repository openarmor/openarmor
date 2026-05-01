# Setting Up Filebeat for OpenArmor

## Overview

Filebeat is a lightweight log shipper that monitors files on disk and forwards their contents to a central processing pipeline. In the OpenArmor stack, Filebeat runs on the monitored Windows endpoint and continuously ships JSON telemetry produced by the OpenArmor agent (`edrsvc.exe`) to Logstash for parsing, enrichment, and indexing into Elasticsearch.

**Data flow:**

```
OpenArmor Agent (edrsvc.exe)
    │ writes JSON events
    ▼
C:\ProgramData\edrsvc\log\output_events\*
    │ Filebeat monitors & ships
    ▼
Logstash :5044 (on Docker host)
    │ parses & enriches
    ▼
Elasticsearch (indexed)
    │
    ▼
Kibana (visualized)
```

Every event the OpenArmor agent records — process creation, network connections, file writes, registry changes — lands in `output_events\` as a JSON file. Filebeat picks up those files and streams them over port 5044 to the Logstash instance running in Docker on your ELK host.

---

## Prerequisites

Before configuring Filebeat, make sure the following are in place:

- **OpenArmor agent installed and running** on the Windows endpoint. Verify that `C:\ProgramData\edrsvc\log\output_events\` exists and contains JSON files.
- **Docker ELK stack running** on your host machine. See [DockerInstallation.md](DockerInstallation.md) for setup instructions.
- **Windows endpoint with Administrator access.** All installation and service management steps require an elevated session.
- **.NET Framework 4.7.2 or later** installed on the endpoint (required by the Filebeat Windows service wrapper).
- **Port 5044 reachable** from the Windows endpoint to the Docker host. If a firewall sits between them, open TCP 5044 inbound on the Docker host.

---

## Installing Filebeat on Windows

### Download the installer

Open PowerShell as Administrator and run:

```powershell
# Download Filebeat 8.x MSI installer
Invoke-WebRequest `
    -Uri "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.0-windows-x86_64.msi" `
    -OutFile "$env:TEMP\filebeat-8.13.0.msi"
```

> **Note:** Check [https://www.elastic.co/downloads/beats/filebeat](https://www.elastic.co/downloads/beats/filebeat) for the latest 8.x release and update the version number in the URL accordingly.

### Run the installer silently

```powershell
Start-Process msiexec.exe -Wait -ArgumentList "/i $env:TEMP\filebeat-8.13.0.msi /quiet"
```

The MSI installer:
- Copies the Filebeat binary to `C:\Program Files\Elastic\Beats\8.x\filebeat\`
- Creates the configuration directory at `C:\ProgramData\Elastic\Beats\filebeat\`
- Registers Filebeat as a Windows service (set to manual start by default)

![Install Filebeat 1](../../assets/screenshots/installing%20filebeat1.avif)

![Install Filebeat 2](../../assets/screenshots/installing%20file%20beat2.avif)

---

## Configuring filebeat.yml

The main configuration file is located at:

```
C:\ProgramData\Elastic\Beats\filebeat\filebeat.yml
```

Open the file in a text editor (run as Administrator) and replace its contents with the following configuration. Substitute `YOUR_DOCKER_HOST` with the actual IP address or hostname of the machine running your Docker ELK stack (see the [Replacing YOUR_DOCKER_HOST](#replacing-your_docker_host) section below).

```yaml
# ============================== Filebeat inputs ==============================
filebeat.inputs:
  - type: filestream
    id: openarmor-events
    enabled: true
    paths:
      - C:\ProgramData\edrsvc\log\output_events\*
    fields:
      source: openarmor
    fields_under_root: true
    encoding: utf-8
    json.keys_under_root: false
    json.add_error_key: true

# ============================== Filebeat modules ==============================
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

# ================================== General ===================================
name: openarmor-${hostname}
tags: ["openarmor", "edr", "windows"]

# ================================= Dashboards =================================
setup.dashboards.enabled: false

# ============================== Kibana setup ==================================
setup.kibana:
  host: "http://YOUR_DOCKER_HOST:5601"
  username: "elastic"
  password: "changeme"

# ================================== Outputs ===================================
output.logstash:
  hosts: ["YOUR_DOCKER_HOST:5044"]

# ================================== Logging ===================================
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\Elastic\Beats\filebeat\logs
  name: filebeat
  keepfiles: 7
  permissions: 0640
```

**Key settings explained:**

| Setting | Purpose |
|---|---|
| `type: filestream` | Uses the modern filestream input (replaces the legacy `log` input) |
| `paths` | Points Filebeat at the OpenArmor event output directory |
| `fields_under_root: true` | Merges the `source: openarmor` field into the root of each event |
| `json.add_error_key: true` | Adds a `_jsonparsefailure` tag if an event cannot be parsed as JSON |
| `name: openarmor-${hostname}` | Tags each event with the originating hostname for multi-endpoint deployments |
| `output.logstash` | Sends events to Logstash on port 5044 instead of directly to Elasticsearch |

![Filebeat Inputs Config](../../assets/screenshots/filebeatinputs-filebeatyaml.avif)

---

## Enabling the Logstash Module

Filebeat ships with a built-in Logstash module that provides pre-built ingest pipelines and dashboards. Enable it from an Administrator PowerShell session:

```powershell
# Change to the Filebeat installation directory
cd "C:\Program Files\Elastic\Beats\8.x\filebeat"

# Enable the logstash module
.\filebeat.exe modules enable logstash --path.config "C:\ProgramData\Elastic\Beats\filebeat"
```

This command creates an active configuration file at `C:\ProgramData\Elastic\Beats\filebeat\modules.d\logstash.yml`.

![Enable Logstash Module](../../assets/screenshots/filebeat-enable-module-logstash.avif)

![Filebeat Modules Config](../../assets/screenshots/filebeatmodules-filebeatyaml.avif)

---

## Configuring the Logstash Module

Edit the newly created module configuration file:

```
C:\ProgramData\Elastic\Beats\filebeat\modules.d\logstash.yml
```

Replace its contents with:

```yaml
- module: logstash
  log:
    enabled: true
    var.paths:
      - C:\ProgramData\edrsvc\log\output_events\*
  slowlog:
    enabled: false
```

**Settings explained:**

- `log.enabled: true` — Activates the log sub-module so Filebeat ingests files from the specified paths.
- `var.paths` — Points the module at the same `output_events\` directory used in `filebeat.yml`. Both entries must match.
- `slowlog.enabled: false` — Disables the Logstash slow-log sub-module, which is not relevant to OpenArmor telemetry.

![Logstash Module Config](../../assets/screenshots/logstashconfig-filebeatyml.avif)

![Logstash YAML](../../assets/screenshots/logstash-yaml.avif)

---

## Starting and Restarting Filebeat

After saving your configuration changes, restart the Filebeat service so it picks up the new settings.

### Option 1: Services GUI

1. Press `Win + R`, type `services.msc`, and press Enter.
2. Scroll down to **Filebeat** in the list.
3. Right-click **Filebeat** and select **Restart**. If the service is not running, select **Start**.

![Services MSC](../../assets/screenshots/services-filebeat-restart.avif)

### Option 2: PowerShell (recommended)

```powershell
# Restart the Filebeat service
Restart-Service -Force filebeat

# Confirm the service is running
Get-Service filebeat
```

Expected output:

```
Status   Name               DisplayName
------   ----               -----------
Running  filebeat           Filebeat
```

![PowerShell Restart](../../assets/screenshots/filebeat-service-restart.avif)

---

## Verifying Filebeat is Working

### Check the Filebeat service status

```powershell
Get-Service filebeat
```

The `Status` column should read `Running`.

### Inspect Filebeat logs

```powershell
# View the last 50 lines of the Filebeat log
Get-Content "C:\ProgramData\Elastic\Beats\filebeat\logs\filebeat" -Tail 50
```

Look for lines similar to the following, which indicate that Filebeat has connected to Logstash and is shipping events:

```
INFO  [publisher_pipeline_output] pipeline/output.go:143  Connection to backoff(async(tcp://YOUR_DOCKER_HOST:5044)) established.
INFO  [beat]  registrar/registrar.go:107  States Loaded from registrar: 1
```

### Confirm OpenArmor is writing events

```powershell
# List files in the OpenArmor event output directory
Get-ChildItem "C:\ProgramData\edrsvc\log\output_events\"
```

There should be one or more `.json` files present. If the directory is empty, confirm that the OpenArmor agent service (`edrsvc`) is running:

```powershell
Get-Service edrsvc
```

### Verify events are arriving in Elasticsearch

Run the following command from the Docker host (or any machine with curl and network access to Elasticsearch):

```bash
curl -u elastic:changeme "localhost:9200/openarmor-*/_count"
```

A response such as the following confirms that events are being indexed:

```json
{"count":142,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}
```

A count of `0` means no events have been indexed yet. Allow a minute or two after starting Filebeat before rechecking, as there may be a short delay before the first batch arrives.

---

## Replacing YOUR_DOCKER_HOST

The placeholder `YOUR_DOCKER_HOST` appears twice in `filebeat.yml` — once for the Kibana setup block and once for the Logstash output. Replace it with the correct value for your environment:

| Environment | Value to use |
|---|---|
| Docker and Filebeat on the same machine | `localhost` or `127.0.0.1` |
| Docker on a different LAN machine | IP address of that machine (e.g., `192.168.1.100`) |
| Docker on a remote server | Hostname or public IP of the server |

**Example** — if your Docker host's LAN IP is `192.168.1.50`:

```yaml
setup.kibana:
  host: "http://192.168.1.50:5601"

output.logstash:
  hosts: ["192.168.1.50:5044"]
```

---

## Troubleshooting

### Filebeat service fails to start

Test the configuration file for YAML syntax errors before starting the service:

```powershell
cd "C:\Program Files\Elastic\Beats\8.x\filebeat"
.\filebeat.exe test config --path.config "C:\ProgramData\Elastic\Beats\filebeat"
```

A successful test prints `Config OK`. If errors are reported, the output will indicate the line number and nature of the problem.

### No events appear in Elasticsearch

Work through the following checklist in order:

1. Confirm the OpenArmor agent is running and producing files in `C:\ProgramData\edrsvc\log\output_events\`.
2. Confirm the Filebeat service is running (`Get-Service filebeat`).
3. Check that the `paths` entries in both `filebeat.yml` and `logstash.yml` match the actual directory.
4. Confirm that port 5044 on the Docker host is reachable from the Windows endpoint:

```powershell
Test-NetConnection -ComputerName YOUR_DOCKER_HOST -Port 5044
```

5. From the Docker host, confirm that Logstash is listening:

```bash
docker ps
docker logs <logstash-container-name> | tail -30
```

### Connection refused on port 5044

- Verify the Docker host IP address is correct.
- Confirm that no firewall (Windows Defender Firewall, cloud security group, etc.) is blocking outbound TCP 5044 from the endpoint or inbound TCP 5044 on the Docker host.
- Confirm the Logstash container is running and the Beats input plugin is active:

```bash
docker logs <logstash-container-name> 2>&1 | grep "Beats inputs"
```

### Test Logstash connectivity directly

```powershell
cd "C:\Program Files\Elastic\Beats\8.x\filebeat"
.\filebeat.exe test output --path.config "C:\ProgramData\Elastic\Beats\filebeat"
```

A successful test ends with `talk to server... OK`.

---

## Next Steps

With Filebeat running and events flowing into Elasticsearch, proceed to configuring the Kibana interface:

- [Setting Up Kibana](SettingKibana.md) — Create data views, explore events in Discover, and build dashboards.
