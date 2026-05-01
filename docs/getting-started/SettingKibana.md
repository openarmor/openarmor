# Setting Up Kibana for OpenArmor

## Overview

Kibana is the visualization and analytics front end for the Elastic Stack. Once OpenArmor telemetry is flowing from Filebeat through Logstash into Elasticsearch, Kibana provides a browser-based interface for searching individual events, building dashboards, and configuring automated alerting rules.

This guide walks through accessing Kibana, creating a data view for OpenArmor events, exploring the event stream in Discover, building a monitoring dashboard, and setting up basic alert rules.

---

## Prerequisites

Before starting, confirm the following:

- **ELK stack running in Docker.** See [DockerInstallation.md](DockerInstallation.md).
- **Filebeat configured and running** on the monitored Windows endpoint. See [SettingFileBeat.md](SettingFileBeat.md).
- **Events flowing into Elasticsearch.** Verify with:

```bash
curl -u elastic:changeme "localhost:9200/openarmor-*/_count"
```

The count should be greater than zero. If it is zero, resolve the Filebeat pipeline first before proceeding.

---

## Accessing Kibana

Open a browser and navigate to:

```
http://YOUR_DOCKER_HOST:5601
```

Replace `YOUR_DOCKER_HOST` with the IP address or hostname of the machine running your Docker ELK stack. If Docker is running on the same machine as your browser, use `localhost`.

**Default credentials:**

| Field | Value |
|---|---|
| Username | `elastic` |
| Password | `changeme` |

> **Important:** Change the default password before exposing your ELK stack to any network. See the [Changing the Default Password](#changing-the-default-password) section at the end of this guide.

![Kibana Welcome](../../assets/screenshots/elastic%20ui1.avif)

---

## Adding the OpenArmor Integration via Logstash

### Navigate to Integrations

From the Kibana home page, click **Integrations** in the left sidebar (or navigate to `http://YOUR_DOCKER_HOST:5601/app/integrations`). In the search box, type **Logstash**.

![Finding Logstash](../../assets/screenshots/elastic%20ui2.avif)

### View Logstash Logs

Select the **Logstash** integration from the results. Scroll down to the **Logstash Logs** section. Because you have already completed the Filebeat configuration, the pipeline is active — this view confirms the integration is recognized by Kibana.

![Logstash Logs](../../assets/screenshots/elastic%20ui3.avif)

---

## Creating a Data View (Index Pattern)

A data view tells Kibana which Elasticsearch indices to query and which field to use as the timestamp. Without a data view, the Discover and Dashboard features cannot display OpenArmor events.

### Steps

1. Navigate to **Stack Management** (gear icon in the left sidebar) → **Data Views**.
2. Click **Create data view**.
3. Fill in the fields:

| Field | Value |
|---|---|
| Name | `OpenArmor Events` |
| Index pattern | `openarmor-*` |
| Timestamp field | `@timestamp` |

4. Click **Save data view to Kibana**.

![Create Data View](../../assets/screenshots/elastic%20ui4.avif)

![Index Pattern](../../assets/screenshots/elastic%20ui5.avif)

> **Tip:** If the index pattern field shows no matching indices, confirm that Filebeat has shipped at least one event and that Elasticsearch has created the index. Run `curl -u elastic:changeme "localhost:9200/_cat/indices?v"` on the Docker host to list all indices.

---

## Exploring Events in Discover

**Discover** is the primary tool for searching and inspecting individual OpenArmor events.

### Opening Discover

1. Navigate to **Analytics** → **Discover** in the left sidebar.
2. In the data view selector (top left of the Discover page), choose **OpenArmor Events**.
3. Set the time range to **Last 24 hours** using the time picker in the top right corner.

### Adding useful columns

By default, Discover shows a single `_source` column containing the full raw event. Add individual fields as columns for a more readable view:

- `processName` — name of the process that generated the event
- `eventType` — OpenArmor event category (e.g., `LLE_PROCESS_CREATE`)
- `severity` — event severity level
- `cmdLine` — full command line of the process
- `remoteAddr` — remote IP address for network events

To add a column, hover over a field name in the left field list and click **+**.

### KQL queries for threat hunting

Kibana Query Language (KQL) lets you filter the event stream without writing raw Elasticsearch queries. Enter these in the search bar above the event list:

```kql
# High-severity events only
severity: "high"
```

```kql
# All PowerShell executions
processName: "powershell.exe"
```

```kql
# Outbound network connections
eventType: "LLE_NETWORK_CONNECT_OUT"
```

```kql
# Process creation events
eventType: "LLE_PROCESS_CREATE"
```

```kql
# Suspicious parent-child: Office spawning a shell
eventType: "LLE_PROCESS_CREATE" AND parentName: "winword.exe"
```

Save any query you want to reuse by clicking **Save** in the Discover toolbar and giving it a descriptive name. Saved searches appear under **Saved Objects** in Stack Management.

---

## Creating a Dashboard

Dashboards give a high-level operational view of endpoint activity across your environment.

### Steps

1. Navigate to **Analytics** → **Dashboard**.
2. Click **Create dashboard**.
3. Click **Create visualization** to add the first panel.

### Recommended panels

Build the following panels for an "OpenArmor Overview" dashboard:

| Panel | Visualization type | Metric / field |
|---|---|---|
| Events over time | Bar chart | X-axis: `@timestamp` (auto-interval); Y-axis: Count |
| Top processes | Pie chart | Slice by: `processName.keyword`; top 10 |
| Events by severity | Donut chart | Slice by: `severity.keyword` |
| Top remote IPs | Data table | Rows: `remoteAddr.keyword`; Metric: Count |
| Event type breakdown | Horizontal bar | X-axis: Count; Y-axis: `eventType.keyword`; top 15 |

After adding each visualization, click **Save and return** to go back to the dashboard canvas.

4. When all panels are in place, click **Save** and name the dashboard **OpenArmor Overview**.

![Dashboard Config](../../assets/screenshots/elastic%20ui6.avif)

![Dashboard Metrics](../../assets/screenshots/elastic%20ui7.avif)

---

## Setting Up Alerts

Kibana's alerting engine can notify you when specific conditions are met in your OpenArmor event data.

### Creating an alert rule

1. Navigate to **Stack Management** → **Rules** (or **Alerts and Insights** → **Rules** depending on your Kibana version).
2. Click **Create rule**.
3. Select **Elasticsearch Query** as the rule type.
4. Configure the rule:

| Setting | Value |
|---|---|
| Name | `OpenArmor High Severity Alert` |
| Check every | `1 minute` |
| Notify | `Only on status change` (or `Every time condition is met`) |

5. Paste the following query into the Elasticsearch query editor:

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "severity": "high" } },
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  }
}
```

6. Set the threshold: **Count is greater than `0`**.
7. Under **Actions**, click **Add action** and choose a connector:
   - **Email** — sends an alert email via an SMTP connector
   - **Slack** — posts a message to a Slack channel via webhook
   - **PagerDuty** — creates an incident in PagerDuty
   - **Index** — writes the alert to an Elasticsearch index for audit purposes

8. Click **Save**.

---

## Useful Saved Searches

Create and save the following searches in Discover for quick access to common investigative views:

| Name | KQL | Purpose |
|---|---|---|
| High Severity | `severity: "high"` | All critical alerts |
| PowerShell Activity | `processName: "powershell.exe"` | PowerShell execution monitoring |
| Network Outbound | `eventType: "LLE_NETWORK_CONNECT_OUT"` | All outbound connections |
| LSASS Access | `eventType: "LLE_PROCESS_OPEN" AND cmdLine: *lsass*` | Credential theft detection |
| Mass File Write | `eventType: "LLE_FILE_WRITE"` | Ransomware-pattern detection |

To save a search: enter the KQL in Discover's search bar, then click **Save** → enter the name → **Save**.

---

## Changing the Default Password

Change the default `elastic` password before putting your ELK stack on any shared or public network. Run the following from the Docker host:

```bash
curl -X POST "localhost:9200/_security/user/elastic/_password" \
  -H "Content-Type: application/json" \
  -u elastic:changeme \
  -d '{"password": "YOUR_NEW_STRONG_PASSWORD"}'
```

After updating, also update:
- The `setup.kibana` credentials in `filebeat.yml` on each monitored endpoint.
- Any Kibana connector credentials configured in alert rules.

---

## Troubleshooting

### No data appears in Discover

1. Check that the selected data view is **OpenArmor Events** (not a default one).
2. Confirm the time range is wide enough — try setting it to **Last 7 days** to rule out a time range mismatch.
3. Verify that Elasticsearch has received events:

```bash
curl -u elastic:changeme "localhost:9200/openarmor-*/_count"
```

4. If the count is zero, return to [SettingFileBeat.md](SettingFileBeat.md) and verify the Filebeat pipeline.

### Cannot connect to Kibana in the browser

1. Verify that the Docker containers are running:

```bash
docker ps
```

Both `kibana` and `elasticsearch` containers should show `Up` in the status column.

2. If a container has exited, restart it:

```bash
docker compose up -d
```

3. Check container logs for startup errors:

```bash
docker logs <kibana-container-name> | tail -50
```

### Authentication error

- Confirm you are using the correct username (`elastic`) and the current password.
- If you have forgotten the password, reset it using the Elasticsearch reset password API from the Docker host:

```bash
docker exec -it <elasticsearch-container-name> \
  bin/elasticsearch-reset-password -u elastic
```

### Data view shows no matching indices

The `openarmor-*` index pattern will not match anything until at least one event has been indexed. Confirm the index exists:

```bash
curl -u elastic:changeme "localhost:9200/_cat/indices/openarmor-*?v"
```

If no indices are listed, the problem is upstream in the Filebeat or Logstash pipeline.

---

## Next Steps

- [Editing Alerting Policies](EditingAlertingPolicies.md) — Customize detection thresholds and notification actions for your environment.
- [Installation Instructions](InstallationInstructions.md) — Return to the main installation overview.
