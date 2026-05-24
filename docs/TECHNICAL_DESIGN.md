# Technical Design Document — ThreatLens

## Overview

ThreatLens is a stateless frontend backed by a stateful FastAPI service and a Supabase PostgreSQL database. Processing is asynchronous: ingest returns immediately with a job ID, and the frontend polls for threats independently of job completion.

---

## Architecture

```
[Log Upload / Paste / File Drop]
          ↓
[FastAPI /ingest — validates, caps size, stores raw_content immutably]
          ↓
[raw_logs — raw_content NEVER modified after insert]
          ↓
[Parser + Redactor — creates redacted copy for LLM; preserves raw_content]
          ↓
[parsed_events]
          ↓
[Rule Engine — deterministic detection on normalized text]
          ↓             ↘
[Rule-matched threats]  [Groq Classifier — ambiguous/unknown logs]
          ↓             ↙
[threats + threat_events tables]
          ↓
[FastAPI /api/threats — polling every 3s]
          ↓
[Next.js Dashboard — plain text rendering, no dangerouslySetInnerHTML]
```

**Rule before AI**: rules run first and catch all obvious cases. Groq only receives logs that rules did not match. This keeps AI costs low, latency low, and makes the system reliable when Groq is unavailable.

---

## Tech Stack

| Layer | Tool | Reason |
|-------|------|--------|
| Frontend | Next.js 16 App Router | SSR + React, Vercel native |
| Backend | FastAPI (Python 3.11) | Async, fast, minimal overhead |
| Database | Supabase (PostgreSQL) | Free tier, instant setup, JSONB support |
| AI Primary | Groq — llama-3.1-8b-instant (classify) + llama-3.3-70b-versatile (explain) | Free tier, fast inference |
| AI Backup | Experimental Gemini Flash | Optional fallback swap if Groq rate-limits |
| Rate limiting | slowapi | FastAPI-native, minimal config |
| Hosting — FE | Vercel free | Next.js native |
| Hosting — BE | Railway free | Always-on, env var management |

---

## Backend Components

### `/api/session` (POST)
Creates a new session server-side. Returns `session_id`, `expires_at`, `max_logs`, `max_explain_calls`. The client stores `session_id` in localStorage. The client NEVER generates its own session ID.

### `/api/ingest` (POST)
1. Validates session (exists, not expired, quota not exceeded)
2. Validates body size (≤3MB), line count (≤500), source_type
3. Inserts raw log record with `processing_status='queued'`
4. Creates `ingestion_jobs` record
5. Launches `BackgroundTask` for processing
6. Returns immediately with `job_id`

**Background processing:**
1. Parse each log line (nginx or auth pattern; fallback to raw)
2. Redact sensitive values from a copy → `redacted_content`
3. Run rule engine on `normalize_for_matching(raw_content)`
4. Write rule-matched threats directly to `threats` table
5. Batch remaining unmatched logs → send to Groq classifier
6. Write AI-classified threats to `threats` table
7. Update job progress counters

### `/api/jobs/{job_id}` (GET)
Returns job progress for frontend progress bar. Frontend polls every 2s during upload.

### `/api/threats` (GET)
Returns threats for a session, newest first. Supports `since=ISO_TIMESTAMP` cursor for incremental polling. Frontend polls every 3s.

### `/api/explain` (POST)
1. Verifies `threat.session_id == request.session_id` (reject mismatch — hard)
2. Checks quota (`used_explain_calls < max_explain_calls`)
3. Returns cached `explanation` if not null (no new Groq call)
4. Otherwise calls Groq llama-3.3-70b-versatile, caches result, returns

### Rate limiting
- 20 requests/minute per IP via slowapi
- Per-session quotas: 500 logs, 10 explain calls (enforced in handlers)
- Groq concurrency: `asyncio.Semaphore(5)` — max 5 concurrent Groq calls globally

---

## Frontend Components

### Session management
On mount, check localStorage for `session_id`. If missing or expired, call `POST /api/session` and store the new ID.

### Upload panel
- Textarea for paste + file drag-and-drop
- Source type selector (nginx / auth / custom)
- "Analyze" button → POST /api/ingest
- Progress bar polling /api/jobs/{job_id} every 2s
- "Load sample attack logs" button (preloads RFC 5737 sample logs)
- "Reset demo" button (creates new session, clears feed)

### Threat feed
- Polls `GET /api/threats?session_id=...&since=...` every 3s
- Appends new threats to feed (newest first)
- Severity badge color: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=gray
- Each threat card: type, severity, source IP, summary, timestamp
- "Explain" button per card

### Explain panel
- Opens on "Explain" click
- Calls `POST /api/explain`
- Displays: explanation text, MITRE tactic, recommended actions list
- Shows "Cached" indicator on subsequent opens

### Stats cards
Frontend-derived from the threat array in state:
```js
const stats = {
  total: threats.length,
  critical: threats.filter(t => t.severity === "CRITICAL").length,
  high:     threats.filter(t => t.severity === "HIGH").length,
  medium:   threats.filter(t => t.severity === "MEDIUM").length,
  low:      threats.filter(t => t.severity === "LOW").length,
}
```

---

## LLM Flow

### Classifier (Groq llama-3.1-8b-instant)
- Input: batch of log lines that did not match any rule
- Prompt: instructs model to treat `<untrusted_logs>` block as untrusted data
- Temperature: 0.1 (consistent JSON output)
- Output: JSON array of findings with threat_type, severity, severity_score, confidence, source_ip, related_event_indices, summary
- Validation: extract JSON, strip markdown fences, validate each field, clamp severity_score/confidence, reject unknown threat types/severities
- On validation failure: mark batch as `failed`, increment `failed_logs`, continue to next batch

### Explain (Groq llama-3.3-70b-versatile)
- Input: threat record + related raw log lines (redacted)
- Output: explanation, MITRE tactic, recommended actions[]
- Cached on `threats.explanation` after first call — never re-fetched unless null
- Quota: 10 calls per session

### Provider abstraction
`LLM_PROVIDER` env var selects the client class at startup. Swapping Groq → Gemini = change env var + redeploy Railway (≈90 seconds, no code change).

---

## Rule Engine Flow

1. For each parsed event batch:
   a. `normalize_for_matching(raw_content)` — URL-decode, HTML-decode, lowercase
   b. Run correlation rules on grouped events (BRUTE_FORCE: 10+ LOGIN_FAILED from same IP in 5 min)
   c. Run pattern rules against normalized text (SQLi, XSS, PATH_TRAVERSAL, PRIV_ESC, SSRF)
2. Before each INSERT: check duplicate suppression (same session_id + threat_type + source_ip within 5 minutes → skip)
3. Write matched threats with `classification_source='rule'`
4. Pass unmatched logs to Groq

---

## Redaction Flow

Applied after parsing, before any LLM call:
- AWS keys, GitHub tokens, JWTs, Bearer/Basic auth headers
- Cookies, passwords, token/secret query params
- Email addresses

`raw_content`: never modified — rule engine and storage always use original.
`redacted_content`: what goes to Groq.

---

## Polling vs Realtime

**Official MVP implementation: polling every 3s.**

Supabase Realtime is post-MVP only. The polling approach:
- Works reliably without RLS setup
- Has no session isolation risk at the browser subscription level
- Supports the `since=ISO_TIMESTAMP` cursor for incremental updates

Supabase Realtime would require verified RLS policies isolating sessions before enabling.

---

## Rate Limits

| Limit | Value | Enforced by |
|-------|-------|-------------|
| Request rate | 20 req/min per IP | slowapi |
| Body size | 3MB | Middleware |
| Logs per session | 500 | Handler |
| Explain calls per session | 10 | Handler |
| Groq concurrency | 5 | asyncio.Semaphore |

---

## Deployment Plan

- **Frontend**: Vercel free tier, linked to GitHub repo, auto-deploy on push
- **Backend**: Railway free tier, env vars set in Railway dashboard, Dockerfile or nixpacks auto-detect
- **Database**: Supabase free tier, schema applied via Supabase SQL editor
- **CORS**: Backend allows only the Vercel domain (`FRONTEND_ORIGIN` env var), not wildcard

---

## Failure Handling

| Failure | Behavior |
|---------|----------|
| Groq returns invalid JSON | Batch marked `failed`, `failed_logs` incremented, job continues |
| Groq rate limit | Semaphore queues calls; if 429 returned, batch marked failed |
| Parser cannot parse line | Stored with `parser_confidence=0.0`, sent to Groq as raw text |
| Supabase connection error | HTTP 500 returned to client with structured error |
| Session expired | HTTP 401 with `session_expired` error code |
| Body > 3MB | HTTP 413 from middleware before handler runs |

---

## Security Controls

- `raw_content` immutable after insert
- Log content rendered as plain text only (`<pre>` tags, no `dangerouslySetInnerHTML`)
- `/api/explain` verifies `threat.session_id == request.session_id`
- CORS: Vercel domain only
- Supabase service role key: backend only, never exposed to frontend
- Groq API key: Railway env var only, never in code or git
- Groq prompts wrap logs in `<logs>` tags marked as untrusted data

---

## Known Technical Tradeoffs

| Decision | Tradeoff |
|----------|----------|
| Polling over WebSocket | Simpler, no connection state, slightly higher latency |
| BackgroundTasks over Celery | No broker needed, but not crash-proof |
| Session token in localStorage | Simpler than cookie auth, but not truly secure |
| Rules before LLM | Lower AI cost, higher reliability, but edge cases go to AI only |
| Free tiers throughout | Zero cost, but rate limits and cold starts are real |
