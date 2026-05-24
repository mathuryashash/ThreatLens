# Risk Register — ThreatLens

## Risk Matrix

| ID | Risk | Impact | Likelihood | Score | Mitigation | Fallback |
|----|------|--------|-----------|-------|-----------|---------|
| R01 | Groq rate limit during demo | HIGH | MEDIUM | 6 | Semaphore(5) + per-session quota | Switch to Gemini: `LLM_PROVIDER=gemini` + redeploy |
| R02 | Groq returns invalid JSON | MEDIUM | LOW | 2 | validate_groq_response() — batch marked failed, job continues | Job completes with failed_logs count; rule-matched threats still show |
| R03 | Groq API outage | HIGH | LOW | 3 | Rule engine runs independently | Demo works for rule-matched threats; explain shows error |
| R04 | Railway cold start on demo | HIGH | MEDIUM | 6 | Keep Railway project alive (free tier sleeps) | Pre-warm by calling /api/health before demo |
| R05 | Supabase connection error | HIGH | LOW | 3 | FastAPI returns 500 with structured error | Show error state in frontend; retry |
| R06 | Vercel deploy failure | HIGH | LOW | 3 | Standard Next.js deploy — rarely fails | Roll back to previous Vercel deployment |
| R07 | Parser misses log format | MEDIUM | MEDIUM | 4 | Fallback to raw payload, sent to Groq | AI classification still produces output; confidence=0.0 |
| R08 | Dashboard not updating | HIGH | LOW | 3 | Polling every 3s; since cursor | Reload page — session persists in localStorage |
| R09 | Cross-session data leak | CRITICAL | LOW | 4 | Session mismatch check; session-scoped queries | Not a production auth failure — demo scope |
| R10 | Prompt injection controls bypass | MEDIUM | LOW | 2 | `<logs>` wrapper + untrusted-data instruction | Accepted residual risk; all output is advisory |
| R11 | Sample logs don't trigger expected threats | HIGH | LOW | 3 | Pre-test sample logs locally before demo | Have screenshots of expected output as backup |
| R12 | Environment variable missing on Railway | HIGH | MEDIUM | 6 | Use deployment checklist; test /api/health after deploy | Check Railway logs immediately; re-add var |
| R13 | CORS misconfiguration | HIGH | LOW | 3 | Set FRONTEND_ORIGIN explicitly; test after deploy | Add Vercel domain to allowed origins |
| R14 | Large upload freezes browser | MEDIUM | LOW | 2 | 3MB cap + 500 line cap | Cap enforced before processing; frontend shows error |
| R15 | Session expires mid-demo | LOW | LOW | 1 | 24h expiry; auto-recreate on 401 | Frontend detects expired session and creates new one |

---

## High-Priority Risks (Score ≥ 5)

### R01 — Groq Rate Limit

**Probability**: Groq free tier has ~30 RPM. 5 concurrent semaphore + per-session quotas reduce call volume, but a busy demo day could hit limits.

**Mitigation**:
- `asyncio.Semaphore(5)` limits concurrent calls
- Per-session 500 log cap and 10 explain cap limit per-user volume
- Groq llama3-8b for classification (cheap calls), 70b only for explain (cached after first call)

**Fallback**:
```
Railway env: LLM_PROVIDER=gemini
Redeploy: ~90 seconds
```
Have Gemini API key ready before demo.

---

### R04 — Railway Cold Start

**Probability**: Railway free tier sleeps after ~5 minutes of inactivity.

**Mitigation**: Send a warm-up request to `GET /api/health` 5 minutes before the demo starts.

**Fallback**: Show a 10-second loading state while the instance warms up. Explain to judges that this is a free-tier cold start, not a bug.

---

### R12 — Missing Environment Variable

**Probability**: Easy to forget one env var when setting up Railway for the first time.

**Mitigation**: Use the env var reference checklist in DEPLOYMENT.md. Call `/api/health` after deploy — it should return 200. Call `POST /api/session` — it should return a UUID.

**Fallback**: Railway dashboard → Environment → add missing var → auto-redeploy.

---

## Demo-Day Contingency Plan

**If Groq explain is slow (>5s)**:
- "Free tier inference can be slow; in production this would use a dedicated endpoint."
- Show the cached result: click Explain a second time — instant return.

**If Groq is completely down**:
- Rule-engine threats still appear (no Groq dependency)
- Show pre-captured screenshot of explain panel
- "AI explanation would appear here — the detection pipeline runs independently of the AI layer."

**If Railway is down**:
- Run backend locally on laptop: `uvicorn main:app --port 8000`
- Update `NEXT_PUBLIC_API_URL` to `http://localhost:8000` in frontend `.env.local`
- Run `npm run dev` locally for frontend too

**If Supabase is down**:
- This is the hardest failure to work around
- Have a video recording of the working demo as absolute fallback

---

## Accepted Risks

| Risk | Why Accepted |
|------|-------------|
| Prompt injection not fully preventable | Mitigated with best available technique; no full solution exists |
| No per-session Supabase RLS | Backend enforces isolation; acceptable for demo scope |
| Session IDs are not cryptographically authenticated | By design — demo scope; not claiming user authentication |
| Redaction misses novel secret formats | Best-effort; documented limitation; users warned |
| BackgroundTasks not crash-proof | Acceptable for hackathon; production would use Celery |
