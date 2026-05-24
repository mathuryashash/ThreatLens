# Implementation Plan — ThreatLens

## Build Rule: MVP before features

Phase 1 must work end-to-end before Phase 2 starts. No polish until Phase 4. No Phase 5 features until everything else is deployed and smoke-tested.

---

## Hour-by-Hour Timeline

```
Hours 0–3    Supabase schema
Hours 3–7    FastAPI skeleton + core endpoints
Hours 7–12   Parser + rule engine
Hours 12–17  Groq pipeline
Hours 17–22  Next.js frontend
─────────────────────────────────
[CHECKPOINT: full end-to-end must work by hour 22]
─────────────────────────────────
Hours 22–26  /explain with caching + explain panel
Hours 26–30  Stats cards, sample loader, demo reset
Hours 30–34  Deploy Vercel + Railway + smoke test
Hours 34–38  Security pass
Hours 38–42  UI polish
Hours 42–47  README, docs, demo video
Hours 47–48  Buffer
```

---

## Phase 1 — End-to-End (Hours 0–22)

**Goal**: Upload logs → see threats in UI. Nothing else matters until this works.

### Task 1.1 — Supabase schema (Hours 0–3)

- [ ] Create Supabase project
- [ ] Run full schema SQL (all 7 tables + all indexes)
- [ ] Verify all CASCADE relationships
- [ ] Test: insert a session, insert a raw_log, verify ON DELETE CASCADE
- [ ] Collect: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`

### Task 1.2 — FastAPI skeleton (Hours 3–5)

- [ ] `pip install fastapi uvicorn supabase python-dotenv slowapi`
- [ ] `main.py` with CORS middleware (localhost for now)
- [ ] Body size middleware (3MB cap)
- [ ] Rate limiter (slowapi, 20/min per IP)
- [ ] `POST /api/session` → creates session, returns session_id
- [ ] Health check: `GET /api/health` → `{"status": "ok"}`
- [ ] Test locally: `curl -X POST localhost:8000/api/session`

### Task 1.3 — Ingest endpoint (Hours 5–7)

- [ ] `POST /api/ingest` — validates session, creates raw_log record, creates job, returns job_id
- [ ] Validation: session exists + not expired, quota check, source_type enum, line count ≤ 500
- [ ] Launch BackgroundTask for processing
- [ ] `GET /api/jobs/{job_id}` — returns job status + progress
- [ ] Test: POST ingest with 2 lines → see raw_logs row in Supabase

### Task 1.4 — Parser (Hours 7–9)

- [ ] nginx access log regex pattern
- [ ] auth log regex patterns (LOGIN_FAILED, PRIV_ESC, SU_FAILED, ACCEPTED)
- [ ] Fallback: unknown format → `parser_confidence=0.0`, store raw in `payload.raw`
- [ ] `normalize_for_matching(text)` — URL-decode, HTML-decode, lowercase
- [ ] Test: parse each sample log type, verify fields
- [ ] Test: double-encoded path traversal normalizes to `../`

### Task 1.5 — Rule engine (Hours 9–12)

- [ ] Pattern rules: SQLI (5 patterns), XSS (4 patterns), PATH_TRAVERSAL (5 patterns), PRIV_ESC (3 patterns), SSRF (2 patterns)
- [ ] Correlation rules: BRUTE_FORCE (10+ LOGIN_FAILED from same IP in 5 min), PORT_SCAN (15+ distinct ports, stretch)
- [ ] `is_duplicate_threat()` check before every INSERT
- [ ] Write to `threats` with `classification_source='rule'`
- [ ] Write to `threat_events` linking threat → parsed_events
- [ ] Test: run each sample log through rule engine, verify correct threat type

### Task 1.6 — GET /api/threats (Hours 12–13)

- [ ] Query threats by session_id, ordered by detected_at DESC
- [ ] Support `since` cursor parameter (optional at this stage)
- [ ] Return correct response shape

### Task 1.7 — Next.js frontend (Hours 13–22)

- [ ] `npx create-next-app@latest frontend --typescript --tailwind --app`
- [ ] Session management: check localStorage, call `POST /api/session` if missing/expired
- [ ] Upload panel: textarea + file drop, source type selector, submit button
- [ ] POST /api/ingest on submit
- [ ] Poll `GET /api/jobs/{job_id}` every 2s for progress bar
- [ ] Poll `GET /api/threats?session_id=...` every 3s
- [ ] Threat feed: render threat cards with type, severity badge, source_ip, summary, timestamp
- [ ] Severity badge colors: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=gray
- [ ] Stats cards: CRITICAL / HIGH / MEDIUM / LOW counts (frontend-derived)

**Checkpoint**: Load sample SSH brute force logs → see BRUTE_FORCE HIGH in the feed. Full loop works.

---

## Phase 2 — Explain (Hours 22–26)

**Goal**: Click Explain → AI explanation appears and caches.

- [ ] `POST /api/explain` endpoint
  - [ ] Verify `threat.session_id == request.session_id` (reject mismatch)
  - [ ] Check quota (`used_explain_calls < max`)
  - [ ] Return cached explanation if `threats.explanation != null`
  - [ ] Call Groq llama3-70b with explain prompt
  - [ ] Cache result in `threats.explanation`
  - [ ] Increment `used_explain_calls`
- [ ] Explain panel in Next.js:
  - [ ] "Explain" button on each threat card
  - [ ] Slide-out or modal panel with explanation text
  - [ ] MITRE tactic badge
  - [ ] Recommended actions list
  - [ ] "Cached" indicator on subsequent clicks
- [ ] Test: click explain → panel opens. Click again → cached flag shows, no second Groq call.
- [ ] Test: explain from different session → 403

---

## Phase 3 — Groq Classifier (Hours 12–17)

*(Can be built in parallel with frontend if time allows, but Phase 1 rule engine is required first)*

**Goal**: Logs not matched by rules get classified by Groq.

- [ ] `LLMClient` abstract base class with `classify_logs()` and `explain_threat()` methods
- [ ] `GroqClient` implementation
  - [ ] `asyncio.Semaphore(5)` for concurrent call cap
  - [ ] Classifier prompt (system + user templates from TRD)
  - [ ] Batch logs not matched by rules → send to Groq
  - [ ] `validate_groq_response()` — extract JSON, validate all fields
  - [ ] On validation failure: mark batch failed, increment `failed_logs`, continue job
  - [ ] Write validated findings to `threats` with `classification_source='ai'`
- [ ] Redactor function — apply all redaction patterns to produce `redacted_content`
  - [ ] Set `redacted_content` on raw_log record
  - [ ] Set `redaction_applied=true`
- [ ] Test: upload log that has no rule match → Groq classifies it → appears in feed with `classification_source='ai'`
- [ ] Test: mock Groq returning invalid JSON → batch fails gracefully, job continues

---

## Phase 4 — Polish + Deploy (Hours 26–42)

**Goal**: Live on Vercel + Railway, demo-ready, security-hardened.

### Polish

- [ ] `since=ISO_TIMESTAMP` cursor on `/api/threats` (incremental polling)
- [ ] Job progress bar (live update from `/api/jobs/{job_id}`)
- [ ] **"Load sample attack logs"** button — preloads all 7 sample log sets
- [ ] **"Reset demo"** button — creates new session, clears UI state
- [ ] Empty state: "No threats detected yet. Upload logs to get started."
- [ ] Loading state on explain button while Groq responds
- [ ] Error state: if ingest fails, show user-facing message
- [ ] Error state: if explain fails, show retry option

### Deploy

- [ ] Create Railway project, add backend, set all env vars
- [ ] Create Vercel project, add frontend, set `NEXT_PUBLIC_API_URL`
- [ ] Set `FRONTEND_ORIGIN` on Railway to Vercel URL
- [ ] Smoke test full demo against deployed URLs
- [ ] Verify no CORS errors in browser console

### Security pass

- [ ] Audit: no `dangerouslySetInnerHTML` for log content
- [ ] Audit: no raw log data injected into HTML attributes
- [ ] Test: XSS payload in log → renders as text
- [ ] Test: prompt injection in log → ignored by AI
- [ ] Test: 3MB+ file → 413 before processing
- [ ] Test: cross-session explain → 403
- [ ] Verify `GROQ_API_KEY` not in any frontend bundle

---

## Phase 5 — Stretch (Hours 42–47, only if ahead of schedule)

Do NOT start Phase 5 until Phase 4 is fully deployed and demo-tested.

- [ ] `/api/stats` endpoint (add only if frontend-derived stats feel slow)
- [ ] IP geolocation (ipapi.co, with `ip_cache` table — 1000/day free limit)
- [ ] `GeminiClient` implementation (emergency swap target)
- [ ] Virtual scrolling (TanStack Virtual, only if list > 200 items)
- [ ] Supabase Realtime (only after verifying RLS isolates sessions)

---

## What to Cut If Behind Schedule

**Cut immediately:**
- IP geolocation
- `/api/stats` endpoint (use frontend-derived)
- Supabase Realtime
- Mobile polish
- Heatmap (use count cards)
- Virtual scrolling

**Never cut:**
- End-to-end upload → rule detection → threat feed
- Groq classifier (Phase 3)
- Explain with caching (Phase 2)
- Sample logs button
- Demo reset button
- Deploy on Vercel + Railway
- Severity badges + stats cards

---

## Verification Checkpoints

| Checkpoint | Hour | Criteria |
|------------|------|----------|
| Schema live | 3 | All 7 tables exist in Supabase |
| Ingest works | 7 | POST /api/ingest inserts raw_log, creates job |
| Rule engine works | 12 | Sample SQLi log → SQLI threat in Supabase |
| Frontend renders threats | 22 | Full end-to-end loop: upload → see threat in browser |
| Explain works | 26 | Click Explain → panel opens; second click shows cached |
| Groq classifies | 17 | Non-rule log → ai-classified threat in feed |
| Deployed | 34 | Live URLs, smoke test passes |
| Demo-ready | 42 | All manual demo tests pass |
