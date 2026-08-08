# ThreatLens — Security Log Triage Dashboard

> A session-scoped security log triage dashboard for nginx and Linux auth events. Paste logs, the backend runs deterministic rules for common attacks, sends unmatched lines to a Groq-hosted Llama model for advisory classification, and shows prioritized explanations in a session-scoped feed.

**Live demo:** https://threatlenss.vercel.app — backend: https://threatlens-qd5e.onrender.com

---

## What it does

1. Parses and normalizes nginx access logs / Linux auth logs
2. Runs deterministic rules (SQLi, brute force, path traversal, SSRF, XSS, privilege escalation)
3. Sends unmatched logs to the LLM for advisory classification
4. Displays a live threat feed with severity badges
5. Click any threat for a plain-English Analyst Brief (MITRE tactic + explanation + recommended actions)

**All output is advisory only. No automated blocking, no agent, no login required.**

---

## Features

- **No signup** — paste logs directly for triage
- **Log upload** — paste / drag-and-drop file (3MB / 500 lines / 8KB per line)
- **Sample log file** — `sample_attack_logs.log` at repo root (see [docs/SAMPLE_LOGS.md](docs/SAMPLE_LOGS.md))
- **One-click incident scenarios** — SSH Brute Force, SSRF Probe, SQL Injection, Priv Esc, Mixed Scan
- **Deterministic rule engine first** — cheap, fast, reliable (ADR-0001)
- **Groq LLM classifier** — catches edge cases rules miss; 20 lines/batch, 5 concurrent
- **3-second polling feed**, severity badges, stats cards, demo reset
- **Prompt injection defense** — logs wrapped in `<logs>` XML tags, labeled untrusted
- **LLM hallucination check** — `source_ip` validated against parsed events before storage

---

## Tech Stack

| Layer | Tool |
|---|---|
| Frontend | Next.js 16 App Router, React 19, Tailwind 4 — **Vercel** |
| Backend | FastAPI (Python, slowapi rate limits) — **Render** |
| Database | Supabase PostgreSQL (in-memory mock fallback) |
| AI | Groq llama-3.1-8b-instant (classify), llama-3.3-70b-versatile (explain); optional Gemini swap |

---

## Quickstart (Local)

```bash
# Backend — http://localhost:8000
cd backend
cp .env.example .env        # fill keys; ALLOW_MOCK_DB=true for keyless demo
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend — http://localhost:3000
cd frontend
cp .env.example .env.local  # NEXT_PUBLIC_API_URL=http://localhost:8000
npm install
npm run dev
```

Supabase optional: apply `docs/optional/DATABASE_SCHEMA.md` SQL, else run with `ALLOW_MOCK_DB=true`.

---

## Deployment & Connection Settings

### Vercel (frontend)

| Setting | Value |
|---|---|
| Root Directory | `frontend` |
| Framework | Next.js |
| `NEXT_PUBLIC_API_URL` | `https://threatlens-qd5e.onrender.com` (no trailing `/`) |

### Render (backend)

| Setting | Value |
|---|---|
| Start command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` | Supabase project |
| `GROQ_API_KEY`, `LLM_PROVIDER=groq` | LLM |
| `FRONTEND_ORIGIN` | `https://threatlenss.vercel.app` — must byte-match; **no trailing slash** |
| `ALLOW_MOCK_DB` | `false` |

Render free tier sleeps idle — keep the `/api/health` endpoint pinged externally (e.g. UptimeRobot, 5-min interval) and the in-app keepalive loop stays warm.

### Known connection gotchas (all handled in code)

| Symptom | Cause | Fix |
|---|---|---|
| "API Server offline" in browser | CSP `connect-src` missing backend domain (Next.js headers) | whitelist `https://*.onrender.com` in `next.config.ts` |
| Requests refused silently | CORS — `FRONTEND_ORIGIN` mismatch (byte-exact) | set exact Vercel URL |
| Stuck "offline" while server healthy | rate limit keyed on shared Cloudflare edge IP | `cf-connecting-ip` key in `main.py` |
| Slow first load | Render free-tier spin-down | external monitor ping |

---

## Architecture

```
Browser (Next.js) ── polls /api/threats every 3s ──┐
      │  POST /api/ingest (async job)              │
      ▼                                            ▼
   FastAPI (main.py)                        Supabase/Postgres
   parser → redactor → rules → LLM            sessions, raw_logs,
      (unmatched → Groq, 20/batch)            parsed_events, threats,
                                               threat_events, ingestion_jobs
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Scope & Limitations

**Is:** demo-grade triage · nginx/auth logs · rules-first, AI-assisted · session-scoped, no accounts · advisory only

**Is NOT:** a SIEM/WAF/IDS · continuous ingestion · automated response · retention system · guaranteed detection

- Session IDs are demo namespace tokens, not credentials (ADR-0004)
- Redaction is best-effort — never upload production secrets
- LLM output is advisory and can misclassify; rules run first (ADR-0001)

---

## Documentation

| Doc | Purpose |
|---|---|
| [SAMPLE_LOGS.md](docs/SAMPLE_LOGS.md) | Sample attack log file — contents & how to demo |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Full deploy guide (Vercel + Render + Supabase) |
| [API_SPEC.md](docs/API_SPEC.md) | API reference |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System diagrams |
| [PRD.md](docs/PRD.md) / [TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md) | Requirements & design |
| [SECURITY.md](docs/SECURITY.md) | Security design |
| [ERD.md](docs/ERD.md) / [TEST_PLAN.md](docs/TEST_PLAN.md) | Schema & tests |
| [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Demo script |

---

## License

Hackathon project — Yashash Mathur