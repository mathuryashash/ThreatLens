# Data Flow Diagram — ThreatLens

## Overview

Data flows through three main pipelines:
1. **Ingestion pipeline** — logs enter, get processed, produce threats
2. **Polling pipeline** — threats flow from database to frontend
3. **Explain pipeline** — user requests explanation for a specific threat

---

## 1. Ingestion Pipeline

```
User (browser)
    │
    │  POST /api/ingest
    │  { session_id, source_type, logs[] }
    │
    ▼
FastAPI — /api/ingest handler
    │
    ├── Validate session (exists, not expired, quota)
    ├── Validate request (body ≤ 3MB, lines ≤ 500, source_type valid)
    ├── INSERT raw_logs { raw_content, processing_status='queued' }
    ├── INSERT ingestion_jobs { status='queued', total_logs }
    ├── Return { job_id, ingested_count, remaining_quota }
    │
    └── [BackgroundTask launched]
            │
            ▼
        Parser
            │
            ├── nginx pattern → { ip, method, path, status, timestamp }
            ├── auth pattern → { ip, username, action, timestamp }
            └── fallback → { payload.raw, parser_confidence=0.0 }
            │
            ▼
        Redactor (runs on raw_content, produces redacted_content)
            │
            ├── Replace: AWS keys, GitHub tokens, JWTs
            ├── Replace: Authorization headers, cookies
            ├── Replace: password=, token=, api_key= params
            └── Replace: email addresses
            │
            ├── UPDATE raw_logs SET redacted_content, redaction_applied=true
            │
            ▼
        INSERT parsed_events (normalized fields)
            │
            ▼
        Rule Engine (runs on normalize_for_matching(raw_content))
            │
            ├── Pattern rules: SQLI, XSS, PATH_TRAVERSAL, PRIV_ESC, SSRF
            ├── Correlation rules: BRUTE_FORCE (group by IP + time window)
            │
            ├── Rule matched → is_duplicate_threat() check
            │       │
            │       ├── Duplicate: skip
            │       └── Not duplicate: INSERT threats { classification_source='rule' }
            │                         INSERT threat_events
            │
            └── Not matched → collect into Groq batch
                    │
                    ▼
                Groq Classifier (llama3-8b)
                    │
                    ├── Build prompt with <logs> block from redacted_content
                    ├── asyncio.Semaphore(5) — acquire before call
                    ├── Call Groq API (temperature=0.1)
                    │
                    ├── validate_groq_response()
                    │       ├── Extract JSON (strip markdown fences)
                    │       ├── Validate each field
                    │       └── Clamp/coerce out-of-range values
                    │
                    ├── status=ok → INSERT threats { classification_source='ai' }
                    │              INSERT threat_events
                    └── status=failed → UPDATE ingestion_jobs failed_logs++
                                        continue to next batch

            UPDATE ingestion_jobs { status='completed', processed_logs, failed_logs }
            UPDATE raw_logs { processing_status='processed' }
```

### Trust Boundaries in Ingestion

```
[ User-controlled: logs[] content ] ← UNTRUSTED
     │
     │  stored as-is in raw_content (immutable)
     │
[ Rule engine: reads normalized copy only ]
[ Redactor: strips known secrets before LLM ]
     │
     │  redacted_content crosses this boundary
     ▼
[ Groq API ] ← receives redacted content only, inside <logs> XML wrapper
```

---

## 2. Polling Pipeline

```
Frontend (setInterval 3s)
    │
    │  GET /api/threats?session_id=X&since=T&limit=50
    │
    ▼
FastAPI — /api/threats handler
    │
    ├── Validate session
    ├── SELECT threats WHERE session_id=X AND detected_at > T
    │   ORDER BY detected_at DESC LIMIT 50
    │
    └── Return { threats[], total, by_severity, next_cursor }
    │
    ▼
Frontend
    ├── Append new threats to feed (newest at top)
    ├── Update since cursor = threats[0].detected_at
    └── Recompute stats cards from full threats array
```

**Polling cursor design**: `since=ISO_TIMESTAMP` ensures only new threats are fetched on each tick. The first poll (no `since`) fetches all threats for the session. Subsequent polls fetch only threats newer than the last seen.

---

## 3. Explain Pipeline

```
User clicks "Explain" on a threat card
    │
    │  POST /api/explain
    │  { session_id, threat_id }
    │
    ▼
FastAPI — /api/explain handler
    │
    ├── Validate session (exists, not expired, quota check)
    ├── Fetch threat by threat_id
    ├── Verify threat.session_id == request.session_id [SECURITY CHECK]
    │
    ├── threat.explanation != null?
    │       ├── YES → return { explanation, mitre_tactic, recommended_actions, cached: true }
    │       │
    │       └── NO → fetch related log lines (redacted_content from raw_logs via threat_events)
    │                    │
    │                    ▼
    │               Groq Explainer (llama3-70b)
    │                    │
    │                    ├── Build explain prompt with threat details + redacted logs
    │                    └── Return explanation, mitre_tactic, recommended_actions[]
    │                    │
    │               UPDATE threats SET explanation=...
    │               UPDATE sessions SET used_explain_calls++
    │                    │
    │               Return { explanation, mitre_tactic, recommended_actions, cached: false }
    │
    ▼
Frontend
    └── Open explain panel with content
```

---

## Data at Rest

| Data | Where | Access |
|------|-------|--------|
| raw_content | Supabase raw_logs | Backend only (service role key) |
| redacted_content | Supabase raw_logs | Backend only; this is what Groq sees |
| threats | Supabase threats | Backend reads; frontend reads via API |
| explanation | Supabase threats.explanation | Cached after first Groq call |
| session_id | Supabase sessions + browser localStorage | Browser sends as bearer token |

---

## Data in Transit

| Flow | Transport | Notes |
|------|-----------|-------|
| Browser → FastAPI | HTTPS | Vercel → Railway, CORS-restricted |
| FastAPI → Supabase | HTTPS | Service role key in Authorization header |
| FastAPI → Groq | HTTPS | API key in Authorization header; only redacted content sent |
| FastAPI → Frontend | HTTPS | Threat data, job status, explain responses |

---

## Data That Never Crosses the LLM Boundary

- `raw_content` (only `redacted_content` goes to Groq)
- AWS keys, GitHub tokens, JWTs (stripped by redactor)
- Full cookie headers (stripped)
- Password fields (stripped)
- `GROQ_API_KEY` itself (Railway env var only)
- `SUPABASE_SERVICE_ROLE_KEY` (Railway env var only)
