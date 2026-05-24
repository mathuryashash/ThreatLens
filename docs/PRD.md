# Product Requirements Document — ThreatLens

## Product Name
ThreatLens — Security Threat Monitoring Dashboard

## One-Line Pitch
A security monitoring dashboard that turns raw server logs into near-real-time threat findings using deterministic rules and AI-assisted explanation.

---

## Problem Statement

Security teams and developers running servers accumulate gigabytes of logs — nginx access logs, SSH auth logs, application logs. Threats hide in this noise: brute force attempts, SQL injection probes, privilege escalation, path traversal. Current options are:

- **Full SIEMs** (Splunk, Elastic) — expensive, complex, overkill for small teams or demos
- **Manual grep** — slow, misses cross-event correlation, produces no explanation
- **Nothing** — most common outcome; attacks go unnoticed

There is no lightweight tool that takes raw logs, detects obvious threats immediately, and produces plain-English explanations for the ones that need human review.

---

## Target Users

**Primary:** Developers and security-aware engineers who run their own servers or VPCs and want quick insight into whether their logs contain attack patterns — without deploying a full SIEM.

**Secondary:** Security students and CTF players who want to understand what attack patterns look like in real logs.

**Out of scope:** Enterprise security operations centers running production SIEMs.

---

## User Pain Points

- "I know there are attacks in my logs but I can't tell which ones matter."
- "I don't want to set up Elastic/Splunk just to check if someone is brute-forcing my SSH."
- "My logs contain something suspicious but I don't know what attack it is or how serious it is."
- "I want to understand the security event in plain English, not just a regex match."

---

## Core Value Proposition

Upload raw logs, get a prioritized threat feed with AI-generated plain-English explanations in under 30 seconds. No setup, no auth, no infrastructure.

---

## Main User Flows

### Flow 1: Upload and detect
1. User opens dashboard — session created automatically
2. User pastes log text or drops a file
3. User clicks "Analyze"
4. Threat feed populates with detected threats (severity-ordered)
5. User sees stats: X critical, Y high, Z medium

### Flow 2: Explain a threat
1. User sees a HIGH threat in the feed
2. User clicks "Explain"
3. Panel opens with: plain-English explanation, MITRE tactic, recommended actions
4. Explanation is cached — subsequent opens are instant

### Flow 3: Sample logs demo
1. User clicks "Load sample attack logs"
2. Pre-built log set (brute force, SQLi, SSRF, path traversal, PRIV_ESC) is ingested
3. Threats appear in feed within seconds
4. User explores the dashboard

### Flow 4: Demo reset
1. User clicks "Reset demo"
2. New session created, feed cleared
3. Ready for another demo or fresh upload

---

## MVP Features

- Session creation (server-generated, stored in localStorage)
- Log upload: paste text or file drop (up to 3MB, 500 lines)
- nginx access log parser
- Linux auth/sshd/sudo log parser
- Rule engine: BRUTE_FORCE, SQLI, XSS, PATH_TRAVERSAL, PRIV_ESC, SSRF
- Groq LLM classifier for logs not matched by rules
- Near-realtime threat feed (polling every 3s)
- Severity badges: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Explain panel with AI explanation (cached after first call, max 10 per session)
- Stats cards (total, by severity)
- Sample attack logs loader
- Demo reset button
- Body size enforcement (3MB max)
- Rate limiting (20 req/min per IP)
- Redaction before LLM (API keys, tokens, passwords, JWTs)

---

## Stretch Features (Phase 5 only, do not build early)

- IP geolocation (country/city on threat cards)
- Supabase Realtime push (replace polling)
- /api/stats endpoint
- Gemini Flash fallback client
- Virtual scrolling for large threat lists (>200 items)
- Hybrid classification (rule + AI combined)

---

## Non-Goals

- User authentication or multi-user accounts
- Automated blocking or firewall rule generation
- Production SIEM capabilities
- Support for arbitrary log formats beyond nginx and Linux auth
- Persistent storage across sessions (24-hour expiry)
- Email or webhook alerting
- Historical trend analysis
- Real-time streaming (WebSocket/SSE)

---

## Success Metrics (Demo)

- User uploads sample logs → threats appear within 5 seconds
- All 5 attack categories in sample logs are detected
- Explain panel loads in under 3 seconds
- Prompt injection log does not produce elevated threat or follow injected instructions
- Benign traffic log produces no threats
- Demo reset creates a clean session with empty feed

---

## Demo Flow (for judges)

1. Open dashboard → session auto-created
2. Click "Load sample attack logs" → 6 attack categories + benign traffic ingested
3. Watch threat feed populate (brute force HIGH, SQLi HIGH, SSRF CRITICAL, path traversal MEDIUM, PRIV_ESC CRITICAL)
4. Click the SSRF threat → explain panel shows MITRE: Initial Access, recommended actions
5. Point out: benign traffic produced no threats
6. Point out: prompt injection log in the batch did not affect AI output
7. Click "Reset demo" → clean session

---

## Known Limitations (to state honestly to judges)

- Session IDs are demo-scoped namespace tokens, not authentication credentials
- AI classification produces false positives — rules handle obvious cases first
- Background job processing is not crash-proof (persists in Postgres but not a durable queue)
- Polling is the realtime mechanism — Supabase Realtime is post-MVP
- Redaction is best-effort — users should not upload logs containing real production secrets
- No automated blocking or remediation — all output is advisory only
- Parser supports nginx access logs and Linux auth/sshd/sudo logs only, with raw fallback
- This is a demo-grade build, not a production SIEM
