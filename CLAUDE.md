# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ThreatLens** — a demo-grade security log triage dashboard. Developers paste nginx or Linux auth logs, the backend runs deterministic rules for common attacks, sends unmatched lines to an LLM for advisory classification, and shows prioritized explanations in a session-scoped feed. Output is advisory only.

## Development Commands

### Backend (FastAPI + Python)

```bash
cd backend
cp .env.example .env        # fill in keys before first run
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

No test runner is configured yet. To verify imports work: `python -c "from app.main import app"`.

Database init: run the SQL in `docs/optional/DATABASE_SCHEMA.md` against your Supabase project.

### Frontend (Next.js)

```bash
cd frontend
cp .env.example .env.local  # set NEXT_PUBLIC_API_URL=http://localhost:8000
npm install
npm run dev      # http://localhost:3000
npm run build
npm run lint
```

**Warning:** This project uses Next.js 16 and React 19.

## Architecture

```
Browser (Next.js 16, React 19, Tailwind 4)
  └─ Polls /api/threats every 3s
  └─ POSTs to /api/ingest (async job)
  └─ POSTs to /api/explain (on threat click)

FastAPI (backend/app/main.py)
  ├─ POST /api/session    — creates scoped demo session (stored in localStorage)
  ├─ POST /api/ingest     — enqueues background job (FastAPI BackgroundTasks)
  ├─ GET  /api/jobs/{id}  — job progress polling
  ├─ GET  /api/threats    — threat feed (session-scoped)
  └─ POST /api/explain    — LLM explanation, cached in DB

Processing pipeline (per ingest job):
  1. parser.py   — normalizes nginx access or Linux auth/sshd/sudo lines
  2. redactor.py — best-effort PII/secret scrubbing before LLM sees content
  3. rules.py    — deterministic regex rules (SSRF, PRIV_ESC, SQLI, BRUTE_FORCE, PATH_TRAVERSAL, XSS)
  4. llm.py      — unmatched logs batched (20/batch, 5 concurrent) → Groq llama-3.1-8b-instant classify
                   explain calls use llama-3.3-70b-versatile

Database (Supabase PostgreSQL):
  Sessions → raw_logs → parsed_events → threats → threat_events (join)
  Dual-mode: SupabaseDatabase (production) | MockDatabase (in-memory, when env keys absent)
```

## Key Design Invariants

- **Rules run before LLM** (ADR-0001): deterministic rules are cheap and reliable; LLM only gets what rules miss.
- **Raw logs are immutable** (ADR-0003): redacted copies are derived and stored separately; only redacted content is sent to the LLM.
- **Polling, not WebSockets** (ADR-0002): frontend polls every 3 seconds; no Supabase Realtime dependency.
- **Session namespace isolation** (ADR-0004): session IDs are demo-scope tokens, not auth credentials. All DB queries filter by `session_id`.
- **Prompt injection defense**: logs are wrapped in `<logs>` XML tags in the system prompt and explicitly labeled untrusted data. Never interpolate raw log content into prompt instructions.
- **LLM hallucination check**: `source_ip` returned by the LLM is validated against IPs extracted from parsed events before being stored.

## Environment Variables

See `backend/.env.example`. Key vars:

| Var | Purpose |
|-----|---------|
| `DATABASE_URL` | Direct Postgres connection string |
| `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` | Supabase API access |
| `LLM_PROVIDER` | `groq` (default) or `gemini` |
| `GROQ_API_KEY` / `GEMINI_API_KEY` | LLM credentials |
| `FRONTEND_ORIGIN` | CORS allowed origin |

Frontend: `NEXT_PUBLIC_API_URL` — defaults to `http://localhost:8000`.

## Backend Module Map

| File | Role |
|------|------|
| `app/main.py` | FastAPI app, all routes, background job worker |
| `app/database.py` | `SupabaseDatabase` + `MockDatabase` (offline fallback); `db` singleton auto-selects |
| `app/rules.py` | Regex rule engine; returns unmatched events for LLM |
| `app/llm.py` | `LLMClient` ABC → `GroqClient` / `GeminiClient`; `get_llm_client()` factory |
| `app/parser.py` | Parses nginx and auth log lines into structured dicts |
| `app/redactor.py` | Scrubs IPs, tokens, passwords before LLM submission |
| `app/schemas.py` | Pydantic v2 request/response models |
| `app/config.py` | `settings` singleton from env vars |

## Frontend Component Map

All components live in `frontend/src/components/`:

| Component | Role |
|-----------|------|
| `Header.tsx` | Session ID display, API status, reset button |
| `StatsCards.tsx` | Severity count badges (CRITICAL/HIGH/MEDIUM/LOW/INFO) |
| `UploadPanel.tsx` | Log text area, file drag-drop, sample log loader, source type selector |
| `ThreatFeed.tsx` | Scrollable threat list; click triggers explain |
| `ExplainPanel.tsx` | Shows MITRE tactic, explanation, recommended actions for selected threat |

All state and API calls live in `page.tsx`. No state management library.

## Deployment

- Frontend → Vercel (`NEXT_PUBLIC_API_URL` env var points to Railway backend)
- Backend → Railway (env vars injected via Railway dashboard)
- Database → Supabase (schema applied once via SQL editor)

See `docs/DEPLOYMENT.md` for full steps.
