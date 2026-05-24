# ThreatLens — Security Log Triage Dashboard

> A session-scoped security log triage dashboard for nginx and Linux auth events. Developers paste logs, the backend runs deterministic rules for common attacks, sends unmatched lines to a Groq-hosted Llama model for advisory classification, and shows prioritized explanations in a session-scoped feed.

---

## What it does

Paste or upload nginx access logs or Linux auth logs. ThreatLens:

1. Parses and normalizes each log line
2. Runs deterministic rules to catch obvious attacks (SQLi, brute force, path traversal, SSRF, privilege escalation)
3. Sends unmatched logs to a Groq-hosted Llama model for advisory classification
4. Displays a live threat feed with severity badges
5. Lets you click any threat for a plain-English AI analyst brief

**All output is advisory only. No automated blocking, agent installation, or account login required.**

---

## Features

- **No agent install or account login** — paste logs directly to run triage
- **Log upload** — paste text or drag-and-drop a file (up to 3MB / 500 lines)
- **Sample attack logs** — one-click preload of brute force, SQLi, XSS, SSRF, path traversal, privilege escalation, and benign traffic
- **Deterministic rule engine** — fast, reliable detection for known attack patterns
- **Groq LLM classifier** — catches edge cases rules miss; explains in plain English
- **Near-realtime threat feed** — polling every 3 seconds
- **Severity badges** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Analyst Brief** — click any threat for MITRE tactic, explanation, and recommended actions
- **Stats cards** — threat counts by status and rules/AI hits
- **Demo reset** — one click to start a fresh session
- **Prompt injection defense** — logs are wrapped in `<untrusted_logs>` XML tags in system prompts and explicitly labeled untrusted data

---

## Architecture

```
User uploads logs
      ↓
Next.js Frontend (Vercel)
      ↓
FastAPI Backend (Railway)
      ↓
Parser + Redactor → Rule Engine → Threats table
                 ↘ Groq LLM ↗
      ↓
Supabase PostgreSQL
      ↑
Frontend polls /api/threats every 3s
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram.

---

## Tech Stack

| Layer | Tool |
|-------|------|
| Frontend | Next.js 16 App Router |
| Backend | FastAPI (Python) |
| Database | Supabase (PostgreSQL) |
| AI Primary | Groq — llama-3.1-8b-instant (classify) + llama-3.3-70b-versatile (explain) |
| AI Backup | Experimental Gemini Flash (Optional swap) |
| Hosting | Vercel (frontend) + Railway (backend) |

---

## Quickstart (Local)

### Prerequisites
- Node.js 18+
- Python 3.11+
- Supabase project with schema applied (optional: falls back to in-memory mock DB)

### Backend

```bash
cd backend
cp .env.example .env   # fill in keys
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
cp .env.example .env.local   # set NEXT_PUBLIC_API_URL
npm install
npm run dev
```

### Database

Run the SQL in `docs/optional/DATABASE_SCHEMA.md` against your Supabase project.

---

## Scope & Honest Limitations

**ThreatLens is:**
- A demo-grade log triage dashboard
- Focused on nginx access logs and Linux auth/sshd/sudo logs
- Rules-first, AI-assisted
- Session-scoped (no authentication or accounts)
- Advisory only

**ThreatLens is NOT:**
- A production monitoring dashboard or SIEM/WAF/IDS/EDR
- A continuous log ingestion pipeline
- A system that alerts, blocks, or automatically responds to threats
- A production log retention solution
- A guarantee that all security threats are detected

### Real-World Design Tradeoffs
- **Session IDs** are namespace tokens to scope demo data, not credentials. No RLS is enabled in the demo (application-level isolation only).
- **Redaction** is best-effort and runs client/server-side; never upload production secrets.
- **AI Classification** produces false positives; deterministic rules run first to save cost and increase speed.
- **In-Memory Fallback**: If Supabase credentials are missing, the system falls back to a mock database (if enabled via `THREATLENS_ALLOW_MOCK_DB=true`).

---

## Documentation

| Document | Purpose |
|----------|---------|
| [PRD.md](docs/PRD.md) | Product requirements |
| [TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md) | Architecture and implementation |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System diagrams |
| [ERD.md](docs/ERD.md) | Database schema diagram |
| [API_SPEC.md](docs/API_SPEC.md) | API reference |
| [SECURITY.md](docs/SECURITY.md) | Security design |
| [TEST_PLAN.md](docs/TEST_PLAN.md) | Test cases |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Deployment guide |
| [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | Demo script |
| [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Build timeline |

---

## Author

Yashash Mathur — Hackathon submission
