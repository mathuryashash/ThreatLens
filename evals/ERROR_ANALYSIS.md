# Error analysis (DEV split) and the improvements it drove

All numbers from `evals/results/*_baseline.json` (before) and `evals/results/<provider>_<split>.json`
(after). Tuning used DEV-split errors only; TEST is reported once after the change.

## Baseline DEV errors by category, with root cause
| category / bucket | rules-only misses | Gemini errors | Groq errors | root cause |
|---|---|---|---|---|
| RECON (`/.env`, `/.git/HEAD`, `/actuator/heapdump`, `/server-status`, `/.aws/credentials`) | 5/5 FN | 0 | 0 | No rule for sensitive-file / ops-endpoint probes; these paths carry no attack keyword so they always cost an LLM call. |
| CRED_STUFFING (13 lines, rotating IPs, 1-4 min apart) | 13/13 FN | 0 | 1 FN (final 200 success) | Brute-force correlation is per-IP, >=10 in 5 min; low-and-slow multi-IP stuffing is invisible to it by design. LLM missed that the success line belongs to the run. |
| PASSWORD_SPRAY (6 lines, 6 IPs, 6 min apart) | 6/6 FN | 0 | 5 FN | Same per-IP correlation blind spot; Groq (gpt-oss-20b) did not connect the accounts/subnet across lines. |
| PROMPT_INJECTION (4) | 4/4 FN | 0 (1 mis-typed) | 1 FN | Not a rule category; prompts told the model to ignore instructions but not to *report* them. |
| B64_PAYLOAD, DATA_EXFIL, ANOMALOUS_LOGIN, PERSISTENCE | all FN | 1 FN (`crontab -l`) | 0 | Context-only attacks, expected LLM territory. |
| **False positives: benign neighbours** (`/search?q=blue+sneakers`, `/products`, `/api/health`, Googlebot checkout) | 0 | 4 FP | 0 | Gemini put ordinary neighbouring lines into a finding's `related_event_indices` (a finding about the attacker IP absorbed adjacent page views). |
| **False positives: hard negatives** (typo-then-success login, `sql-injection-prevention-guide`, `q=select+a+union+rep`, CSV export, single 401) | 0 | 4 FP | 5 FP | Security vocabulary without payload, and a single typo login, read as attacks. |

## Improvements (both tuned on DEV only)
1. **Rule: `RECON` sensitive-path probe** (`backend/app/rules.py`). Anchored to the request path
   (`"GET /.env`, `/.git/`, `/.aws/`, `/actuator/`, `/server-status`) so blog slugs and
   `/assets/environment.js` don't match. TDD: `backend/tests/test_eval_improvements.py`
   (5 hits + 5 look-alike negatives, written failing first).
2. **Prompt: `CLASSIFY_GUIDANCE`** appended to both Groq and Gemini classify prompts
   (`backend/app/llm.py`): only index lines that are themselves malicious; vocabulary without payload
   and one typo login are benign; low-and-slow multi-IP/multi-account failures are spraying/stuffing;
   instructions addressed to an AI are prompt injection to *report*.

## Effect
| run | split | precision | recall | F1 | FP | FN |
|---|---|---|---|---|---|---|
| rules | dev | 1.000 -> 1.000 | 0.406 -> 0.500 | 0.578 -> 0.667 | 0 -> 0 | 38 -> 32 |
| rules | **test** | 0.983 -> 0.985 | 0.537 -> 0.593 | 0.695 -> 0.740 | 1 -> 1 | 50 -> 44 |
| rules+Gemini | dev | 0.887 -> 0.955 | 0.984 -> 0.984 | 0.933 -> 0.969 | 8 -> 3 | 1 -> 1 |
| rules+Gemini | **test** | 0.964 -> 0.991 | 0.982 -> 0.991 | 0.973 -> **0.991** | 4 -> 1 | 2 -> 1 |
| rules+Groq | dev | 0.919 -> 1.000 | 0.891 -> 0.984 | 0.905 -> 0.992 | 5 -> 0 | 7 -> 1 |
| rules+Groq | **test** | 0.947 -> 0.955 | 0.991 -> 0.972 | 0.968 -> **0.963** | 6 -> 5 | 1 -> 3 |

Honest reading:
* Gemini's held-out gain is real but small in absolute terms (6 -> 2 errors out of 203 lines).
* **Groq did not improve on TEST** (F1 -0.005, 2 more FNs) despite a large DEV gain - classic
  over-fitting of the prompt to the dev error modes; its remaining TEST FPs are staff admin
  exports (`nginx2:36-39`) that the guidance does not cover.
* LLM outputs are single samples at temperature 0.1; run-to-run variance was not measured
  (re-runs replay from the disk cache, so they are identical by construction).
* The Groq DEV baseline needed a second run: the first hit 429s and 20 lines failed; the second
  completed the failed batch (8 of 9 calls replayed from cache). Reported baseline = the complete run.
* Remaining shared TEST errors: `auth2:15` (benign planned `useradd ... -s /bin/bash`) matches the
  CMD_INJECTION rule `/bin/bash` pattern - a rule false positive left in place on purpose because
  fixing it would mean tuning on a TEST line; `sample_nginx:14` (XSS POST body not in the log line,
  unknowable from the log alone).
