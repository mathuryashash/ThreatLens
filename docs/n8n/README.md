# ThreatLens SOC Agent n8n Workflow

Import `threatlens-soc-agent.workflow.json` into n8n.

## What it does

1. Runs every 15 minutes.
2. Creates a ThreatLens demo session.
3. Loads embedded demo attack logs.
4. POSTs logs to `/api/ingest`.
5. Waits 2 seconds and polls `/api/jobs/{job_id}` until the job is complete.
6. Fetches `/api/threats`.
7. Sends the threat feed to an n8n AI Agent.
8. Agent tools:
   - `lookup_ip_reputation`: deterministic demo IP reputation scores.
   - `get_threat_history`: HTTP Request Tool calling ThreatLens `/api/threats`.
   - `calculate_risk_score`: combines severity, confidence, reputation, repetition, and criticality hints.
9. If risk >= 80, sends Slack if configured, prepares an email report payload, and calls `/api/threats/{id}/dismiss` for the primary threat.
10. Otherwise marks the run done without alerting.

## Required edits after import

Open `Config` and set:

- `base_url`: your backend URL. For Docker Desktop n8n hitting WSL/host backend, try `http://host.docker.internal:8000`. For Railway, use your Railway backend URL.
- `source_type`: `nginx`, `auth`, `syslog`, or `custom`.
- `slack_webhook_url`: optional incoming Slack webhook. If blank, the workflow skips Slack.
- `security_email`: used in `Email Report Payload`.
- `abuseipdb_api_key`: reserved for live AbuseIPDB wiring.

Connect credentials on `OpenAI Chat Model`.

## For real log files

n8n Code nodes should not directly read the filesystem. For real logs, replace `Load Demo Logs` with n8n's `Read/Write Files from Disk` node or a Webhook trigger that receives log lines, then output this JSON shape:

```json
{
  "session_id": "...",
  "base_url": "http://...",
  "source_type": "nginx",
  "logs": ["line 1", "line 2"]
}
```

## For live AbuseIPDB

The included `lookup_ip_reputation` tool is deterministic for demo reliability. To make it live, replace it with an HTTP Request Tool:

- Method: GET
- URL: `https://api.abuseipdb.com/api/v2/check`
- Query:
  - `ipAddress`: `={{ $fromAI('ipAddress', 'IP address to check', 'string') }}`
  - `maxAgeInDays`: `90`
- Headers:
  - `Key`: your AbuseIPDB API key
  - `Accept`: `application/json`
- Tool description: `Check whether an IP is known malicious using AbuseIPDB.`

## Backend endpoint added

This workflow uses:

`POST /api/threats/{threat_id}/dismiss`

Body:

```json
{ "session_id": "..." }
```

The endpoint marks the threat as dismissed by setting `false_positive=true`, matching the existing Supabase schema.

## Production caution

Keep this agent advisory or add human approval before destructive response actions such as firewall blocks. Logs are treated as untrusted input in the agent prompt.
