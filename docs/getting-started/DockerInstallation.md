# Docker Installation Guide

## Overview

OpenArmor uses Docker to host the ELK backend — Elasticsearch, Logstash, and Kibana — on a Linux or Windows server. The OpenArmor Windows agent (`edrsvc.exe`) runs natively on monitored endpoints and ships telemetry events to this stack via Filebeat over the Logstash Beats input (port 5044). Docker provides an isolated, reproducible environment for the entire logging and analytics pipeline without requiring manual installation of each ELK component.

---

## Architecture

```
[Windows Endpoint]              [Docker Host (Linux/Windows)]
OpenArmor Agent                 ┌─────────────────────────────┐
edrsvc.exe                      │  Elasticsearch  :9200        │
    │                           │  Logstash       :5044 :9600  │
    │ Filebeat → :5044 ──────►  │  Kibana         :5601        │
    └──────────────────────────►│                              │
                                └─────────────────────────────┘

Agent log output: C:\ProgramData\edrsvc\log\output_events\
```

Filebeat, installed on each Windows endpoint alongside the OpenArmor agent, tails the agent log directory and forwards JSON events to Logstash. Logstash parses and normalises events before indexing them in Elasticsearch. Kibana provides the search and dashboard interface.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Docker Engine | 20.x+ | Latest stable |
| Docker Compose | v2.x | Latest stable |
| RAM | 8 GB | 16 GB |
| Disk (Elasticsearch data) | 50 GB | 100 GB+ |
| OS | Ubuntu 22.04, WSL2, macOS | Ubuntu 22.04 LTS |

**Ports that must be reachable from Windows endpoints:**

| Port | Service | Purpose |
|---|---|---|
| 5044 | Logstash | Beats input (Filebeat → Logstash) |
| 5601 | Kibana | Web UI (management network only) |
| 9200 | Elasticsearch | REST API (restrict to trusted IPs) |

---

## Linux Installation (Ubuntu / Debian)

The following steps install Docker Engine and the Compose plugin on Ubuntu 22.04 LTS. Run all commands as a user with `sudo` privileges.

### 1. Update the system and install dependencies

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates curl gnupg
```

### 2. Add the Docker GPG key and repository

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
```

### 3. Install Docker Engine

```bash
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 4. Enable and start Docker

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

### 5. Add your user to the docker group (avoids prefixing every command with sudo)

```bash
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect. Verify with:

```bash
docker run --rm hello-world
```

---

## Windows (Docker Desktop)

1. Download Docker Desktop from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop).
2. Run the installer and follow the on-screen prompts.
3. When prompted, select **Use WSL 2 instead of Hyper-V** (recommended).
4. After installation, open Docker Desktop → **Settings** → **Resources** and allocate at least **8 GB RAM** and **4 CPUs**.
5. Apply and restart.

Ensure WSL2 is installed and set as the default version before installing Docker Desktop:

```powershell
wsl --install
wsl --set-default-version 2
```

---

## Deploying the ELK Stack

OpenArmor uses [deviantony/docker-elk](https://github.com/deviantony/docker-elk) as the reference ELK stack. It ships with a pre-configured `docker-compose.yml`, Logstash pipeline, and environment variable file.

### 1. Clone the repository

```bash
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
```

### 2. Set the vm.max_map_count kernel parameter (Linux only)

Elasticsearch requires a higher virtual memory limit than the default Linux kernel setting.

```bash
# Apply immediately (does not survive reboot)
sudo sysctl -w vm.max_map_count=262144

# Persist across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 3. Start the stack

```bash
docker compose up -d
```

Docker will pull the Elasticsearch, Logstash, and Kibana images on the first run. This may take several minutes depending on your connection speed.

![Docker Compose Up](../../assets/screenshots/docker-compose-allup.avif)

---

## Verifying the Stack

### Check container status

```bash
docker compose ps
```

All three containers (`elasticsearch`, `logstash`, `kibana`) should show `running` or `Up` status.

![Docker PS](../../assets/screenshots/docker-ps-list.avif)

### Tail Elasticsearch logs

```bash
docker compose logs elasticsearch | tail -20
```

Wait until you see a line containing `"started"` — this confirms the Elasticsearch node is ready to accept connections.

### Access the web interfaces

| Service | URL | Default credentials |
|---|---|---|
| Kibana | http://localhost:5601 | elastic / changeme |
| Elasticsearch | http://localhost:9200 | elastic / changeme |

Replace `localhost` with the Docker host IP address when accessing from a remote Windows endpoint.

---

## Default Credentials

> **Warning:** Default credentials must be changed before exposing this stack to any production or untrusted network.

| Service | Default Username | Default Password | Change Command |
|---|---|---|---|
| Elasticsearch | `elastic` | `changeme` | `docker compose exec elasticsearch bin/elasticsearch-reset-password -u elastic` |
| Kibana System | `kibana_system` | `changeme` | `docker compose exec elasticsearch bin/elasticsearch-reset-password -u kibana_system` |
| Logstash Internal | `logstash_internal` | `changeme` | Update `LOGSTASH_INTERNAL_PASSWORD` in `.env`, then `docker compose up -d` |

After changing passwords, update the corresponding values in the `.env` file at the root of the `docker-elk` directory and restart affected containers.

---

## Firewall Configuration

On the Docker host, open the ports that Windows endpoints need to reach:

```bash
# Logstash Beats input — required by all monitored endpoints
sudo ufw allow 5044/tcp

# Kibana — restrict to management network or VPN only
sudo ufw allow 5601/tcp

# Elasticsearch REST API — restrict to trusted IPs in production
sudo ufw allow from <trusted-ip-range> to any port 9200 proto tcp

# Apply changes
sudo ufw reload
sudo ufw status
```

On cloud providers (AWS, Azure, GCP), configure the equivalent security group or firewall rule to allow inbound TCP on 5044 from your endpoint subnet.

---

## Production Hardening

Before using this stack in a production environment, complete the following steps:

**Change all default passwords**

Update `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD`, and `LOGSTASH_INTERNAL_PASSWORD` in the `.env` file and restart the stack.

**Enable TLS for Elasticsearch and Kibana**

Follow the [deviantony/docker-elk TLS guide](https://github.com/deviantony/docker-elk#tls-encryption) to generate certificates and enable HTTPS on all services.

**Tune the Elasticsearch JVM heap**

Set the heap to half your available RAM (do not exceed 32 GB). Edit `elasticsearch/config/jvm.options` or set the environment variable in `docker-compose.yml`:

```yaml
environment:
  ES_JAVA_OPTS: "-Xms4g -Xmx4g"
```

**Enable Index Lifecycle Management (ILM)**

Configure an ILM policy to automatically roll over, shrink, and delete old indices. See [SettingELK.md](SettingELK.md) for a ready-made policy.

**Use named persistent volumes**

By default the stack uses Docker named volumes. Verify with:

```bash
docker volume ls | grep docker-elk
```

Do not run `docker compose down -v` in production — this deletes all Elasticsearch data.

---

## Stopping and Restarting the Stack

```bash
# Stop containers without removing them (data is preserved)
docker compose stop

# Start stopped containers
docker compose start

# Remove containers but keep volumes (data is preserved)
docker compose down

# Remove containers AND volumes — WARNING: all Elasticsearch data is deleted
docker compose down -v
```

---

## Troubleshooting

**Elasticsearch exits immediately after starting**

This is almost always caused by an insufficient `vm.max_map_count`. Run:

```bash
sudo sysctl -w vm.max_map_count=262144
docker compose up -d elasticsearch
```

**Kibana reports "Kibana server is not ready yet" or cannot connect to Elasticsearch**

Elasticsearch takes 30–90 seconds to become ready after container start. Wait and refresh. If the issue persists, check Elasticsearch logs:

```bash
docker compose logs elasticsearch | tail -30
```

**Port already in use**

Identify the conflicting process:

```bash
ss -tlnp | grep 5601
ss -tlnp | grep 9200
ss -tlnp | grep 5044
```

Stop the conflicting service or change the port mapping in `docker-compose.yml`.

**Out of memory (OOM) / containers being killed**

Increase the memory limit in Docker Desktop settings (Windows/macOS) or add more RAM to the host (Linux). The ELK stack requires a minimum of 4–6 GB dedicated to Docker.

**Filebeat cannot connect to Logstash from Windows endpoint**

- Confirm the Docker host's firewall allows inbound TCP on 5044.
- Confirm the correct host IP is set in the Filebeat `output.logstash.hosts` field.
- Test connectivity: `Test-NetConnection -ComputerName <docker-host-ip> -Port 5044` from the Windows endpoint.

---

## Next Steps

With the Docker ELK stack running, proceed to:

- [SettingELK.md](SettingELK.md) — Configure Elasticsearch index templates, Logstash pipelines, and ILM policies for OpenArmor telemetry.
- [SettingFileBeat.md](SettingFileBeat.md) — Install and configure Filebeat on Windows endpoints to forward OpenArmor agent logs.
- [SettingKibana.md](SettingKibana.md) — Import OpenArmor dashboards and set up index patterns in Kibana.
