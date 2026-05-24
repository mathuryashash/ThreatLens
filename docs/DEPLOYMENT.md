# Deployment Guide — ThreatLens

## Architecture

- **Frontend**: Vercel (Next.js 16)
- **Backend**: Railway (FastAPI)
- **Database**: Supabase (PostgreSQL)

---

## Step 1 — Supabase Setup

1. Create a new project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** → run the full schema from `docs/optional/DATABASE_SCHEMA.md`
3. From **Project Settings → API**, collect:
   - **Project URL** → `SUPABASE_URL`
   - **service_role key** → `SUPABASE_SERVICE_ROLE_KEY` (backend only, never frontend)
   - **anon key** → `SUPABASE_ANON_KEY` (frontend-safe, but MVP does not use it directly)

---

## Step 2 — Backend on Railway

### Initial setup

1. Create a new project at [railway.app](https://railway.app)
2. Connect your GitHub repo
3. Railway auto-detects Python — it will use `requirements.txt` and a `Procfile` or `railway.toml`

### Procfile (create in `/backend/`)

```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Environment Variables (set in Railway dashboard — never in code)

```env
# Database
SUPABASE_URL=https://<your-project>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<service_role_key>

# LLM
LLM_PROVIDER=groq
LLM_CLASSIFIER_MODEL=llama-3.1-8b-instant
LLM_EXPLAIN_MODEL=llama-3.3-70b-versatile
LLM_PROMPT_VERSION=v1.0
GROQ_API_KEY=<your_groq_key>
GEMINI_API_KEY=<your_gemini_key>

# App limits
MAX_BODY_SIZE_MB=3
MAX_LOGS_PER_SESSION=500
MAX_EXPLAIN_CALLS_PER_SESSION=10
GROQ_MAX_CONCURRENT=5

# CORS
FRONTEND_ORIGIN=https://<your-vercel-app>.vercel.app
```

### Deploy

Push to the connected branch. Railway auto-deploys.

Check logs in the Railway dashboard for startup errors.

### Verify backend is live

```bash
curl https://<your-railway-app>.railway.app/api/session -X POST
# Should return: {"session_id": "...", "expires_at": "...", ...}
```

---

## Step 3 — Frontend on Vercel

### Initial setup

1. Create a new project at [vercel.com](https://vercel.com)
2. Import your GitHub repo
3. Set **Root Directory** to `frontend/` (if monorepo)
4. Framework preset: **Next.js** (auto-detected)

### Environment Variables (set in Vercel project settings)

```env
NEXT_PUBLIC_API_URL=https://<your-railway-app>.railway.app
```

Do **not** put `SUPABASE_SERVICE_ROLE_KEY` or `GROQ_API_KEY` in Vercel env vars.

### Deploy

Push to `main`. Vercel auto-deploys.

### Verify frontend

Open the Vercel URL. The dashboard should load and auto-create a session (check browser localStorage for `session_id`).

---

## Step 4 — CORS Configuration

In the backend, CORS must allow only the Vercel frontend origin:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ["FRONTEND_ORIGIN"]],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
```

`FRONTEND_ORIGIN` must be set as a Railway env var (e.g., `https://threatlens.vercel.app`).

After setting, redeploy Railway.

---

## Step 5 — Smoke Test

Run through this checklist after deploying:

```
□ Open frontend URL in browser
□ DevTools → Application → localStorage → session_id key exists
□ Click "Load sample attack logs"
□ Threat feed populates within 5 seconds
□ CRITICAL/HIGH/MEDIUM threats appear with correct severity badges
□ Click "Explain" on any threat → explanation panel opens
□ Click "Explain" again → "Cached" indicator shows
□ Click "Reset demo" → feed clears, new session_id in localStorage
□ Stats cards show correct counts
□ No CORS errors in browser DevTools console
□ No 401/403 errors in Railway logs for the smoke test session
```

---

## Environment Variables Reference

| Variable | Where | Required | Description |
|----------|-------|----------|-------------|
| `SUPABASE_URL` | Railway | Yes | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Railway | Yes | Service role key (backend only) |
| `SUPABASE_ANON_KEY` | Railway | No | Anon key (not used in MVP) |
| `GROQ_API_KEY` | Railway | Yes | Groq API key |
| `GEMINI_API_KEY` | Railway | No | Gemini API key (optional) |
| `LLM_PROVIDER` | Railway | Yes | `groq` or `gemini` |
| `LLM_CLASSIFIER_MODEL` | Railway | Yes | e.g. `llama-3.1-8b-instant` |
| `LLM_EXPLAIN_MODEL` | Railway | Yes | e.g. `llama-3.3-70b-versatile` |
| `LLM_PROMPT_VERSION` | Railway | Yes | e.g. `v1.0` |
| `MAX_BODY_SIZE_MB` | Railway | Yes | e.g. `3` |
| `MAX_LOGS_PER_SESSION` | Railway | Yes | e.g. `500` |
| `MAX_EXPLAIN_CALLS_PER_SESSION` | Railway | Yes | e.g. `10` |
| `GROQ_MAX_CONCURRENT` | Railway | Yes | e.g. `5` |
| `FRONTEND_ORIGIN` | Railway | Yes | Vercel app URL (no trailing slash) |
| `NEXT_PUBLIC_API_URL` | Vercel | Yes | Railway backend URL (no trailing slash) |

---

## Switching LLM Provider (Experimental Backup)

An optional experimental Gemini client exists in code (via `LLM_PROVIDER=gemini`), but Groq is the primary supported demo path. If you wish to swap to Gemini:

1. Go to Railway dashboard → Environment Variables
2. Change `LLM_PROVIDER` from `groq` to `gemini`
3. Ensure `GEMINI_API_KEY` is set
4. Click "Deploy" (or Railway auto-deploys on env var change)
5. Wait ~90 seconds for redeploy

No code changes required. The provider abstraction handles the swap.

---

## Database Migrations

The schema is applied once via the Supabase SQL editor. There is no migration tool for the hackathon build.

If you need to reset the schema:
1. Drop all tables in Supabase SQL editor
2. Re-run `docs/optional/DATABASE_SCHEMA.md` SQL

---

## Local Development

### Backend

```bash
cd backend
cp .env.example .env    # fill in all values
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
cp .env.example .env.local
# Set: NEXT_PUBLIC_API_URL=http://localhost:8000
npm install
npm run dev
```

Frontend runs on `http://localhost:3000`, backend on `http://localhost:8000`.

For local dev, set `FRONTEND_ORIGIN=http://localhost:3000` in the backend `.env`.
