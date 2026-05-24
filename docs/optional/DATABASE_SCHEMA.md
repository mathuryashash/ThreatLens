# Database Schema — ThreatLens

Run this SQL against your Supabase project in the SQL editor. Order matters — child tables reference parent tables.

---

## Full Schema SQL

```sql
-- ============================================================
-- sessions
-- ============================================================
CREATE TABLE sessions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at          TIMESTAMPTZ DEFAULT now(),
  expires_at          TIMESTAMPTZ DEFAULT now() + INTERVAL '24 hours',
  max_logs            INTEGER DEFAULT 500,
  used_logs           INTEGER DEFAULT 0,
  max_explain_calls   INTEGER DEFAULT 10,
  used_explain_calls  INTEGER DEFAULT 0,
  last_seen_at        TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- raw_logs
-- raw_content is IMMUTABLE after insert — never UPDATE this column
-- ============================================================
CREATE TABLE raw_logs (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id          UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  source_type         TEXT NOT NULL CHECK (source_type IN ('nginx','auth','syslog','custom')),
  raw_content         TEXT NOT NULL,
  redacted_content    TEXT,
  redaction_applied   BOOLEAN DEFAULT false,
  processing_status   TEXT NOT NULL DEFAULT 'queued'
                      CHECK (processing_status IN ('queued','processing','processed','failed')),
  processing_error    TEXT,
  ingested_at         TIMESTAMPTZ DEFAULT now(),
  processed_at        TIMESTAMPTZ
);

CREATE INDEX idx_raw_logs_status  ON raw_logs(processing_status, ingested_at);
CREATE INDEX idx_raw_logs_session ON raw_logs(session_id);

-- ============================================================
-- ingestion_jobs
-- updated_at must be set manually on every UPDATE (no trigger)
-- ============================================================
CREATE TABLE ingestion_jobs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  total_logs      INTEGER NOT NULL,
  processed_logs  INTEGER DEFAULT 0,
  failed_logs     INTEGER DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','processing','completed','failed')),
  error           TEXT,
  created_at      TIMESTAMPTZ DEFAULT now(),
  updated_at      TIMESTAMPTZ DEFAULT now(),
  completed_at    TIMESTAMPTZ
);

-- ============================================================
-- parsed_events
-- ============================================================
CREATE TABLE parsed_events (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  raw_log_id        UUID NOT NULL REFERENCES raw_logs(id) ON DELETE CASCADE,
  session_id        UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  timestamp         TIMESTAMPTZ,
  source_ip         INET,
  destination_ip    INET,
  username          TEXT,
  action            TEXT,
  payload           JSONB,
  parser_confidence REAL CHECK (parser_confidence BETWEEN 0 AND 1),
  created_at        TIMESTAMPTZ DEFAULT now()
);

-- ============================================================
-- threats
-- explanation is cached — written once on first /api/explain call
-- ============================================================
CREATE TABLE threats (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id            UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  threat_type           TEXT NOT NULL CHECK (threat_type IN (
                          'BRUTE_FORCE','PORT_SCAN','SQLI','XSS',
                          'PRIV_ESC','DATA_EXFIL','SSRF','RECON',
                          'PATH_TRAVERSAL','MALWARE','SUSPICIOUS'
                        )),
  severity              TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
  severity_score        INTEGER NOT NULL CHECK (severity_score BETWEEN 1 AND 100),
  confidence            REAL CHECK (confidence BETWEEN 0 AND 1),
  source_ip             INET,
  geo_country           TEXT,
  geo_city              TEXT,
  is_private_ip         BOOLEAN DEFAULT false,
  summary               TEXT,
  explanation           TEXT,
  classification_source TEXT NOT NULL CHECK (classification_source IN ('rule','ai','hybrid')),
  attack_pattern        TEXT,
  model_name            TEXT,
  prompt_version        TEXT,
  false_positive        BOOLEAN,
  raw_ai_response       JSONB,
  detected_at           TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_threats_session_severity ON threats(session_id, severity_score DESC);
CREATE INDEX idx_threats_session_time     ON threats(session_id, detected_at DESC);

-- ============================================================
-- threat_events (join table)
-- ============================================================
CREATE TABLE threat_events (
  threat_id UUID REFERENCES threats(id) ON DELETE CASCADE,
  event_id  UUID REFERENCES parsed_events(id) ON DELETE CASCADE,
  PRIMARY KEY (threat_id, event_id)
);

CREATE INDEX idx_threat_events_event ON threat_events(event_id);

-- ============================================================
-- ip_cache (optional — used only in Phase 5 geolocation)
-- ============================================================
CREATE TABLE ip_cache (
  ip            INET PRIMARY KEY,
  country       TEXT,
  city          TEXT,
  is_private    BOOLEAN DEFAULT false,
  lookup_failed BOOLEAN DEFAULT false,
  looked_up_at  TIMESTAMPTZ DEFAULT now()
);
```

---

## Table Reference

| Table | Purpose |
|-------|---------|
| `sessions` | Tracks user sessions, quotas, expiry |
| `raw_logs` | Immutable log storage — original content preserved forever |
| `ingestion_jobs` | Async job tracking — progress bar data |
| `parsed_events` | Structured log fields extracted by parser |
| `threats` | Detected threats with severity, classification, and cached explanation |
| `threat_events` | Many-to-many: which log events contributed to each threat |
| `ip_cache` | Geolocation lookup cache (Phase 5 only) |

---

## Important Notes

### raw_content is immutable
After `INSERT`, the only columns that should ever be updated on `raw_logs` are:
- `processing_status`
- `processing_error`
- `redacted_content`
- `redaction_applied`
- `processed_at`

Never `UPDATE raw_logs SET raw_content = ...`.

### ingestion_jobs.updated_at
PostgreSQL does not auto-update `updated_at`. Every `UPDATE ingestion_jobs` must include `updated_at = now()` explicitly. There is no trigger.

### Private IP Detection (PostgreSQL)
```sql
SELECT source_ip,
  (source_ip <<= '10.0.0.0/8'::inet OR
   source_ip <<= '192.168.0.0/16'::inet OR
   source_ip <<= '172.16.0.0/12'::inet) AS is_private
FROM parsed_events;
```

### Session Expiry Check (application layer)
```python
# In handlers — before processing any request
if session["expires_at"] < datetime.utcnow().isoformat():
    raise HTTPException(status_code=401, detail={"error": "session_expired"})
```
