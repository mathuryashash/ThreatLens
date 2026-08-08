# Sample Attack Logs

A ready-made log file for demoing ThreatLens without hunting for real logs.

## File

- **Location:** `sample_attack_logs.log` (repo root)
- **Format:** plain text, one log line per entry — safe to open in any editor
- **Size:** ~8 KB, well under the 500-line / 3 MB upload limit
- **Content:** attack and benign lines only — no real user data, no private IPs, no secrets

## What's inside

The file bundles two log formats into one file, with section markers:

| Section | Log format | Sample source | Expected detections |
|---|---|---|---|
| `BENIGN TRAFFIC` | nginx | normal browsing | none (should pass through) |
| SQL injection | nginx | `sqlmap/1.7` | `SQLI` (rule) |
| SSRF | nginx | outbound `/fetch?url=...` | `SSRF` (rule) |
| XSS | nginx | `<script>` in query/path | `XSS` (rule) |
| Path traversal | nginx | `../../etc/passwd` | `PATH_TRAVERSAL` (rule) |
| Brute force | auth/sshd | repeated `Failed password` | `BRUTE_FORCE` (rule) |
| Privilege escalation | auth/sudo | `sudo` failures | `PRIV_ESC` (rule) |
| Recon | nginx | `User-Agent: nmap` / dir probing | rule or AI (`classification_source: ai`) |

Unmatched / non-obvious lines are batched to the Groq LLM (`llama-3.1-8b-instant`) for
advisory classification, so the demo also exercises the AI path.

## How to use

1. Open the dashboard
2. **UploadPanel → Load Sample** (loads the lines into the editor), or drag `sample_attack_logs.log` onto the upload area
3. Source type: `nginx` for the web lines, `auth` for the sshd/sudo lines (the log markers indicate which section is which; splitting the file and running each half with its matching source type gives the cleanest results)
4. Click **Run Analysis** — job completes in a few seconds (LLM classification is the slow part)
5. Click any threat in the feed to open the **Analyst Brief** (MITRE tactic + explanation + recommended actions)

## Expected result

- ~90–95% of the log lines detected by rules, the remainder by the AI classifier
- Severity badges populated (CRITICAL/HIGH/MEDIUM/LOW)
- `statscards` show rule hits vs AI hits
- Note: **false positives are normal** — e.g. any `127.0.0.1` / `10.x` source can trigger SSRF-style rules even on benign lines. That's the documented tradeoff of the deterministic engine (see `docs/optional/RULE_ENGINE.md`).

## Data it needs

The demo runs with **no Supabase schema** and **no API keys** if `ALLOW_MOCK_DB=true`
is set (in-memory session, nothing persisted). For the full experience (cached
explanations, job persistence), point `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`
at a Supabase project with the schema from `docs/optional/DATABASE_SCHEMA.md` applied.