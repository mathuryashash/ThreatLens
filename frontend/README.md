# ThreatLens — Frontend

Next.js 16 App Router + React 19 + Tailwind 4 dashboard for the ThreatLens security log triage backend.

## Setup

```bash
cp .env.example .env.local   # NEXT_PUBLIC_API_URL=http://localhost:8000
npm install
npm run dev                  # http://localhost:3000
```

## Key files

- `src/app/page.tsx` — all state + API calls (polling loop, ingest jobs, session handling)
- `src/components/` — Header, StatsCards, UploadPanel (scenarios), ThreatFeed, ExplainPanel
- `next.config.ts` — security headers (CSP `connect-src` — keep backend host whitelisted) + API rewrites

## Env vars

| Var | Purpose |
|---|---|
| `NEXT_PUBLIC_API_URL` | Backend base URL (no trailing slash) |

See root `README.md` for deployment (Vercel) settings.