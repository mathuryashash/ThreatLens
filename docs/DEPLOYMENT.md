# Deployment Guide — ThreatLens

Current production topology:

- **Frontend** → Vercel (`https://threatlenss.vercel.app`)
- **Backend** → Render (`https://threatlens-qd5e.onrender.com`)
- **Database** → Supabase (PostgreSQL, schema in `docs/optional/DATABASE_SCHEMA.md`)

---

## 1. Backend → Render

1. Render dashboard → **New Web Service** → connect the GitHub repo
2. Root directory: `backend` (Dockerfile auto-detected; or use start command `uvicorn main:app --host 0.0.0.0 --port $PORT`)
3. Environment variables:

| Var | Value |
|---|---|
| `SUPABASE_URL` | `https://<project>.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key |
| `GROQ_API_KEY` | Groq key |
| `LLM_PROVIDER` | `groq` |
| `FRONTEND_ORIGIN` | `https://threatlenss.vercel.app` — exact, no trailing slash |
| `ALLOW_MOCK_DB` | `false` |
| `RENDER_EXTERNAL_URL` | auto-injected by Render (supports the keepalive loop) |

4. **Keep free tier awake**: Render free instances sleep after ~15 min idle. Set up an external monitor — UptimeRobot → New Monitor → HTTP → `https://<your-service>.onrender.com/api/health`, 5-min interval. The in-app keepalive (`_keepalive_loop` in `app/main.py`) can only self-ping while awake.

## 2. Frontend → Vercel

1. Vercel → New Project → import GitHub repo → Root Directory `frontend`
2. `NEXT_PUBLIC_API_URL=https://<your-service>.onrender.com` (no trailing slash)
3. «Deploy»

⚠️ **CSP**: `next.config.ts` headers set `Content-Security-Policy: connect-src ...`. If you change backend hosts, add the new domain (e.g. `https://*.onrender.com`) or the browser silently blocks all API calls (console: *"violates the document's Content Security Policy"*).

## 3. Post-deploy sanity checklist

- `curl https://<frontend>/` → 200
- `curl https://<backend>/api/health` → `{"status":"ok",...}`
- Preflight: `curl -i -X OPTIONS -H "Origin: https://<frontend>" -H "Access-Control-Request-Method: POST" https://<backend>/api/session` → `access-control-allow-origin: https://<frontend>`
- Browser: load a scenario → Run Analysis → threat appears → Brief generates (LLM)

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "API Server offline" banner | CSP missing backend domain in `next.config.ts`; or `FRONTEND_ORIGIN` mismatch on Render (must byte-match, no trailing slash) |
| Stuck offline while server healthy | rate limit keyed on shared Cloudflare edge IP — code uses `cf-connecting-ip`; restart service after deploy |
| Very slow first request | Render free-tier cold start; external monitor prevents |
| 500 on all DB endpoints | Supabase env vars missing/wrong, or project paused |

## 5. Local dev with Docker

```bash
docker-compose up
# frontend http://localhost:3000, backend http://localhost:8000
```