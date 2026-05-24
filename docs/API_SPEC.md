# API Specification — ThreatLens

## Base URL

- **Production**: `https://<your-railway-app>.railway.app`
- **Local**: `http://localhost:8000`

All endpoints are prefixed with `/api`.

---

## Session Model

Sessions are namespace tokens, not authentication credentials. A `session_id` (UUIDv4) is:
- Generated server-side on `POST /api/session`
- Stored by the client in `localStorage`
- Passed as a query parameter or request body field on all subsequent calls
- Valid for 24 hours
- Scoped: data from one session is never readable by another session

**There is no user authentication.** Session IDs should be treated as opaque bearer tokens for demo isolation only.

---

## Error Response Format

All errors return JSON:

```json
{
  "error": "error_code",
  "detail": "human readable description"
}
```

### Common Error Codes

| Code | HTTP Status | Meaning |
|------|------------|---------|
| `session_not_found` | 404 | session_id does not exist |
| `session_expired` | 401 | session past expires_at |
| `quota_exceeded` | 429 | used_logs >= max_logs |
| `explain_quota_exceeded` | 429 | used_explain_calls >= max_explain_calls |
| `invalid_source_type` | 400 | source_type not in allowed set |
| `request_too_large` | 413 | body > 3MB |
| `too_many_lines` | 400 | more than 500 log lines |
| `threat_not_found` | 404 | threat_id does not exist |
| `session_mismatch` | 403 | threat.session_id != request session_id |
| `rate_limited` | 429 | 20 req/min per IP exceeded |
| `classification_failed` | 500 | Groq returned invalid/unparseable response |

---

## Endpoints

### POST /api/session

Creates a new session. Call on app load if no valid session exists in localStorage.

**Request**: No body required.

**Response `200`**:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2025-05-24T14:32:00Z",
  "max_logs": 500,
  "max_explain_calls": 10
}
```

---

### POST /api/ingest

Ingest a batch of log lines for analysis. Processing is asynchronous — this endpoint returns immediately.

**Request body**:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_type": "nginx",
  "logs": [
    "203.0.113.42 - - [23/May/2025:14:33:01 +0000] \"GET /api/users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\" 400 512",
    "203.0.113.42 - - [23/May/2025:14:33:02 +0000] \"GET /api/login?user=admin'+OR+1=1-- HTTP/1.1\" 400 512"
  ]
}
```

**Fields**:
| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| session_id | UUID string | Yes | Must exist and not be expired |
| source_type | string | Yes | `nginx` \| `auth` \| `syslog` \| `custom` |
| logs | string[] | Yes | Max 500 items; total body max 3MB |

**Response `200`**:
```json
{
  "status": "queued",
  "job_id": "7f3a1b2c-...",
  "ingested_count": 2,
  "remaining_quota": 498
}
```

**Errors**: `session_not_found`, `session_expired`, `quota_exceeded`, `invalid_source_type`, `request_too_large`, `too_many_lines`

---

### GET /api/jobs/{job_id}

Poll for processing progress. Frontend polls every 2s during upload to drive the progress bar.

**Path parameter**: `job_id` — UUID returned by `/api/ingest`

**Query parameter**: `session_id` — must match the job's session

**Response `200`**:
```json
{
  "job_id": "7f3a1b2c-...",
  "status": "processing",
  "total_logs": 20,
  "processed_logs": 12,
  "failed_logs": 0,
  "percent_complete": 60
}
```

**Status values**: `queued` | `processing` | `completed` | `failed`

**Errors**: `session_not_found`, `session_expired`, `threat_not_found` (job not found), `session_mismatch`

---

### GET /api/threats

Fetch threats for the current session. Supports incremental polling via `since` cursor.

**Query parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | UUID string | Yes | Session to scope results to |
| severity | string | No | Filter: `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` \| `INFO` |
| limit | integer | No | Max results to return (default 50, max 200) |
| since | ISO 8601 timestamp | No | Return only threats detected after this time (for polling cursor) |

**Response `200`**:
```json
{
  "threats": [
    {
      "id": "a1b2c3d4-...",
      "session_id": "550e8400-...",
      "threat_type": "SQLI",
      "severity": "HIGH",
      "severity_score": 80,
      "confidence": 0.95,
      "source_ip": "203.0.113.42",
      "geo_country": null,
      "geo_city": null,
      "is_private_ip": false,
      "summary": "SQL injection probe targeting /api/users endpoint",
      "explanation": null,
      "classification_source": "rule",
      "attack_pattern": "UNION SELECT",
      "model_name": null,
      "detected_at": "2025-05-23T14:33:01Z"
    }
  ],
  "total": 1,
  "by_severity": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "next_cursor": "2025-05-23T14:33:01Z"
}
```

**Errors**: `session_not_found`, `session_expired`

**Polling pattern** (frontend):
```js
let since = null
const poll = async () => {
  const url = since
    ? `/api/threats?session_id=${sid}&since=${since}&limit=50`
    : `/api/threats?session_id=${sid}&limit=50`
  const data = await fetch(url).then(r => r.json())
  if (data.threats.length > 0) {
    appendToFeed(data.threats)
    since = data.threats[0].detected_at  // newest first
  }
}
setInterval(poll, 3000)
```

---

### POST /api/explain

Fetch a plain-English explanation for a threat. Returns cached explanation if already generated.

**Request body**:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "threat_id": "a1b2c3d4-..."
}
```

**Response `200`**:
```json
{
  "threat_id": "a1b2c3d4-...",
  "explanation": "The attacker attempted a UNION-based SQL injection against the /api/users endpoint. By appending 'UNION SELECT username,password FROM users', they were probing to extract credential data from the database. The server returned HTTP 400, suggesting the attack was blocked at the application layer, but the attempt indicates active reconnaissance.",
  "mitre_tactic": "Initial Access",
  "recommended_actions": [
    "Review WAF rules to ensure UNION SELECT patterns are blocked",
    "Audit /api/users for parameterized query usage",
    "Check if any 200 responses preceded this 400 for the same IP",
    "Consider rate-limiting this IP at the load balancer"
  ],
  "cached": false
}
```

**On second call for same threat_id**:
```json
{
  "threat_id": "a1b2c3d4-...",
  "explanation": "...",
  "mitre_tactic": "Initial Access",
  "recommended_actions": [...],
  "cached": true
}
```

**Errors**: `session_not_found`, `session_expired`, `explain_quota_exceeded`, `threat_not_found`, `session_mismatch`, `classification_failed`

**Security note**: The backend verifies `threat.session_id == request.session_id`. A threat from one session cannot be explained by a request from another session — returns `403 session_mismatch`.

---

### GET /api/stats *(Phase 5 — optional)*

Returns aggregated stats for a session. In MVP, these stats are derived on the frontend from the threats array.

**Query parameters**: `session_id`

**Response `200`**:
```json
{
  "total": 12,
  "by_severity": {
    "CRITICAL": 2,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
  },
  "by_type": {
    "SQLI": 3,
    "BRUTE_FORCE": 2,
    "SSRF": 1,
    "PATH_TRAVERSAL": 2,
    "PRIV_ESC": 1,
    "XSS": 1,
    "SUSPICIOUS": 2
  },
  "classification_breakdown": {
    "rule": 8,
    "ai": 4
  }
}
```

---

## Rate Limits

| Limit | Value | Scope |
|-------|-------|-------|
| Request rate | 20 requests/minute | Per source IP |
| Log quota | 500 lines | Per session (lifetime) |
| Explain quota | 10 calls | Per session (lifetime) |
| Body size | 3MB | Per request |
| Groq concurrency | 5 | Global (backend semaphore) |

Rate limit exceeded returns HTTP `429` with `Retry-After` header.
