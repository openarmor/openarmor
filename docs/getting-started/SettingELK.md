# Setting Up Elasticsearch, Logstash, and Kibana for OpenArmor

## Overview

This guide configures the ELK stack specifically to receive, parse, and index telemetry from the OpenArmor Windows agent. After completing the steps below, Elasticsearch will hold structured OpenArmor event data in a dedicated index pattern, Logstash will apply OpenArmor-specific parsing rules, and Kibana will be ready to query and visualise the data.

This guide assumes the Docker ELK stack is already deployed and running. If you have not done that yet, complete [DockerInstallation.md](DockerInstallation.md) first.

---

## Prerequisites

- Docker ELK stack running (all three containers: `elasticsearch`, `logstash`, `kibana`)
- OpenArmor agent (`edrsvc.exe`) installed on at least one Windows endpoint
- Agent log output directory: `C:\ProgramData\edrsvc\log\output_events\`
- `curl` available on the Docker host (for API calls)
- `git` available on the Docker host

---

## Clone the ELK Stack Repository

If you have not already cloned the reference stack, do so now:

```bash
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
```

![Git Clone ELK](../../assets/screenshots/git-clone-elk.avif)

The repository contains a pre-configured `docker-compose.yml`, a default Logstash pipeline, and an `.env` file for passwords. All configuration in this guide is applied on top of this base.

---

## Starting the Stack

Set the required kernel parameter and start all services:

```bash
# Required by Elasticsearch on Linux hosts
sudo sysctl -w vm.max_map_count=262144

# Start Elasticsearch, Logstash, and Kibana in the background
docker compose up -d
```

![Docker Compose Up](../../assets/screenshots/docker-compose-allup.avif)

Confirm all containers are running:

```bash
docker compose ps
```

![Docker PS](../../assets/screenshots/docker-ps-list.avif)

Wait approximately 60 seconds after `docker compose up -d` before proceeding. Elasticsearch must complete its bootstrap sequence before accepting API requests. Tail the logs to confirm readiness:

```bash
docker compose logs elasticsearch | tail -20
# Ready when you see: "started" in the output
```

---

## Elasticsearch Index Template for OpenArmor

An index template tells Elasticsearch how to map fields in incoming OpenArmor documents. Without this template, Elasticsearch will auto-detect field types, which can cause mapping conflicts (for example, an IP address being indexed as a plain string instead of the `ip` type).

Create the template via the Elasticsearch REST API:

```bash
curl -X PUT "localhost:9200/_index_template/openarmor" \
  -H "Content-Type: application/json" \
  -u elastic:changeme \
  -d '{
    "index_patterns": ["openarmor-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1
      },
      "mappings": {
        "properties": {
          "@timestamp":   { "type": "date" },
          "pid":          { "type": "long" },
          "processName":  { "type": "keyword" },
          "processPath":  { "type": "keyword" },
          "cmdLine":      { "type": "text" },
          "eventType":    { "type": "keyword" },
          "severity":     { "type": "keyword" },
          "remoteAddr":   { "type": "ip" },
          "filePath":     { "type": "keyword" }
        }
      }
    }
  }'
```

A successful response looks like:

```json
{"acknowledged": true}
```

**Field reference:**

| Field | Type | Description |
|---|---|---|
| `@timestamp` | date | Event time (set by Logstash from agent timestamp) |
| `pid` | long | Process ID of the subject process |
| `processName` | keyword | Executable name (e.g. `powershell.exe`) |
| `processPath` | keyword | Full path to the executable |
| `cmdLine` | text | Full command line (full-text searchable) |
| `eventType` | keyword | OpenArmor event category (e.g. `ProcessCreate`, `NetworkConnect`) |
| `severity` | keyword | Agent-assigned severity level |
| `remoteAddr` | ip | Remote IP address for network events |
| `filePath` | keyword | File path for file system events |

---

## Logstash Pipeline for OpenArmor

Create a dedicated Logstash pipeline configuration file that parses OpenArmor JSON events arriving from Filebeat.

Create the file at `logstash/pipeline/openarmor.conf` inside the `docker-elk` directory:

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][source] == "openarmor" {
    json {
      source => "message"
      target => "event"
    }
    date {
      match => ["[event][timestamp]", "UNIX_MS"]
      target => "@timestamp"
    }
    mutate {
      add_field => { "[@metadata][index]" => "openarmor-%{+YYYY.MM.dd}" }
    }
  }
}

output {
  elasticsearch {
    hosts    => ["elasticsearch:9200"]
    index    => "%{[@metadata][index]}"
    user     => "logstash_internal"
    password => "${LOGSTASH_INTERNAL_PASSWORD}"
  }
}
```

**Pipeline explanation:**

- **input**: Listens on port 5044 for Beats connections (Filebeat on each Windows endpoint).
- **filter**: Only processes events where Filebeat has tagged the source as `openarmor`. The `json` filter parses the raw agent log message into structured fields. The `date` filter promotes the agent's millisecond-precision UNIX timestamp to `@timestamp`, which Kibana uses for time-series display. The `mutate` filter sets the daily index name.
- **output**: Writes to Elasticsearch using the `logstash_internal` service account. The password is read from the environment variable set in the `.env` file — never hard-code credentials in the pipeline file.

After creating the file, reload the pipeline without restarting the container:

```bash
docker compose exec logstash bin/logstash --config.reload.automatic
```

Or restart Logstash:

```bash
docker compose restart logstash
```

Verify the pipeline loaded successfully:

```bash
docker compose logs logstash | grep -i "pipeline"
# Expected: "Pipeline started successfully"
```

---

## ILM Policy (Log Retention)

An Index Lifecycle Management policy automatically manages index growth and retention. The policy below rolls over the active index when it reaches 10 GB or 7 days old, moves it to warm tier at 7 days, and deletes it after 30 days. Adjust these values to match your retention requirements and storage capacity.

```bash
curl -X PUT "localhost:9200/_ilm/policy/openarmor-ilm" \
  -H "Content-Type: application/json" \
  -u elastic:changeme \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "actions": {
            "rollover": {
              "max_size": "10gb",
              "max_age": "7d"
            }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "shrink": {
              "number_of_shards": 1
            }
          }
        },
        "delete": {
          "min_age": "30d",
          "actions": {
            "delete": {}
          }
        }
      }
    }
  }'
```

Attach the ILM policy to the `openarmor` index template by adding a `lifecycle` block to the template settings:

```bash
curl -X PUT "localhost:9200/_index_template/openarmor" \
  -H "Content-Type: application/json" \
  -u elastic:changeme \
  -d '{
    "index_patterns": ["openarmor-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
        "index.lifecycle.name": "openarmor-ilm",
        "index.lifecycle.rollover_alias": "openarmor"
      }
    }
  }'
```

---

## Verifying Data Flow

Once Filebeat is configured on a Windows endpoint (see [SettingFileBeat.md](SettingFileBeat.md)), use these commands to confirm events are reaching Elasticsearch.

### List OpenArmor indices

```bash
curl -u elastic:changeme "localhost:9200/_cat/indices/openarmor-*?v"
```

Expected output (one line per day with events):

```
health status index                uuid  pri rep docs.count docs.deleted store.size pri.store.size
green  open   openarmor-2024.01.15 ...    1   1       1523            0      1.2mb          640kb
```

### Check document count

```bash
curl -u elastic:changeme "localhost:9200/openarmor-*/_count"
```

Expected output:

```json
{"count": 1523, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}}
```

If the count remains at zero after several minutes of Filebeat running, proceed to the Troubleshooting section.

### Query a sample document

```bash
curl -u elastic:changeme \
  "localhost:9200/openarmor-*/_search?pretty&size=1"
```

This returns a single indexed OpenArmor event in full, which is useful for confirming field mappings are applied correctly.

---

## Default Credentials

> **Warning:** Change the default credentials immediately on any internet-accessible deployment.

| Account | Default Username | Default Password |
|---|---|---|
| Elasticsearch superuser | `elastic` | `changeme` |
| Kibana service account | `kibana_system` | `changeme` |
| Logstash output account | `logstash_internal` | `changeme` |

Passwords are set in the `.env` file at the root of the `docker-elk` directory. After editing `.env`, restart the relevant containers:

```bash
docker compose up -d
```

---

## Troubleshooting

**No `openarmor-*` indices appear in Elasticsearch**

1. Confirm Logstash is running and the pipeline loaded: `docker compose logs logstash | grep -i pipeline`
2. Confirm Filebeat on the Windows endpoint can reach the Docker host on port 5044: `Test-NetConnection -ComputerName <docker-host-ip> -Port 5044`
3. Check Filebeat logs on the Windows endpoint for connection errors.
4. Confirm the `fields.source` value in the Filebeat config matches the value in the Logstash filter (`openarmor`).

**Mapping conflict errors in Elasticsearch logs**

A field type mismatch between the index template and incoming data will cause indexing failures. Delete the conflicting index (data loss) and recreate the template:

```bash
curl -X DELETE "localhost:9200/openarmor-*" -u elastic:changeme
# Then re-run the index template creation command above
```

**Authentication failures (401 Unauthorized)**

- Verify that the password in your `curl` command matches the value in `.env`.
- If passwords were recently changed, restart all containers: `docker compose down && docker compose up -d`
- Check Logstash for auth errors: `docker compose logs logstash | grep -i "unauthorized\|401"`

**Logstash pipeline fails to load**

Check for syntax errors in `openarmor.conf`:

```bash
docker compose exec logstash bin/logstash -f /usr/share/logstash/pipeline/openarmor.conf --config.test_and_exit
```

Fix any reported errors and reload.

**Elasticsearch heap out of memory**

Set the JVM heap in `docker-compose.yml` under the `elasticsearch` service:

```yaml
environment:
  ES_JAVA_OPTS: "-Xms4g -Xmx4g"
```

Do not set the heap above 50% of available RAM, and never above 32 GB.

---

## Next Steps

With the ELK stack configured for OpenArmor telemetry, proceed to:

- [SettingFileBeat.md](SettingFileBeat.md) — Install Filebeat on Windows endpoints and point it at the OpenArmor agent log directory (`C:\ProgramData\edrsvc\log\output_events\`).
- [SettingKibana.md](SettingKibana.md) — Create the `openarmor-*` index pattern in Kibana and import pre-built dashboards.
