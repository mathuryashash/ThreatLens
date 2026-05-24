# Deployment Guide — ThreatLens

## Stack
- Frontend → Vercel
- Backend → Railway
- Database → Supabase (already configured)

## Prerequisites
- GitHub repo with this code pushed
- Vercel account (vercel.com)
- Railway account (railway.app)

## Backend → Railway

1. Go to railway.app → New Project → Deploy from GitHub repo
2. Select the repo, set **Root Directory** to `backend`
3. Railway auto-detects the Dockerfile
4. Add environment variables in Railway dashboard:
   - SUPABASE_URL
   - SUPABASE_SERVICE_ROLE_KEY
   - GROQ_API_KEY
   - LLM_PROVIDER=groq
   - FRONTEND_ORIGIN=https://your-vercel-url.vercel.app
5. Deploy — Railway gives you a URL like `https://threatlens-backend.railway.app`

## Frontend → Vercel

1. Go to vercel.com → New Project → Import GitHub repo
2. Set **Root Directory** to `frontend`
3. Add environment variable:
   - NEXT_PUBLIC_API_URL=https://your-railway-url.railway.app
4. Deploy — Vercel gives you a URL like `https://threatlens.vercel.app`

## After Deploy

Update Railway → FRONTEND_ORIGIN to your Vercel URL (for CORS).

## Local Dev with Docker

```bash
docker-compose up
```

Frontend: http://localhost:3000
Backend: http://localhost:8000
