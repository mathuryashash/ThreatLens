# Head-to-head on the held-out TEST split (203 lines, 108 attacks)

Same runner (`evals/run.py`), same pipeline (parser -> redactor -> rules -> unmatched lines to the LLM in batches of 20). API rows are the cached results from branch `hermes/threatlens-evals` (not re-run). Latency = per 20-line LLM batch (local: RTX 4060 Laptop, transformers generate, greedy). Cost = API list price estimate; local = $0 API spend (electricity not counted).

| run | model | P | R | F1 | cat-acc | FP | FN | hard-neg FP | JSON valid | LLM batches | p50 s | p95 s | est. $ | failed lines | file |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| rules only | `none` | 0.985 | 0.593 | **0.740** | 0.583 | 1 | 44 | 1/31 | n/a | 0 | None | None | $0.0000 | 0 | `rules_test.json` |
| rules + Qwen2.5-0.5B base (local, no LoRA) | `Qwen2.5-0.5B-Instruct-bnb-4bit` | 0.985 | 0.593 | **0.740** | 0.583 | 1 | 44 | 1/31 | 1.000 (9/9) | 9 | 11.406 | 15.028 | $0.0000 | 0 | `local_test_base.json` |
| rules + Qwen2.5-0.5B QLoRA v1 data (local) | `Qwen2.5-0.5B-Instruct-bnb-4bit+lora` | 0.674 | 0.861 | **0.756** | 0.741 | 45 | 15 | 19/31 | 0.889 (8/9) | 9 | 13.808 | 104.132 | $0.0000 | 0 | `local_test_ft_v1.json` |
| rules + Qwen2.5-0.5B QLoRA v2 data (local) | `Qwen2.5-0.5B-Instruct-bnb-4bit+lora` | 0.822 | 0.685 | **0.748** | 0.667 | 16 | 34 | 6/31 | 1.000 (9/9) | 9 | 26.714 | 61.244 | $0.0000 | 0 | `local_test_ft_v2.json` |
| rules + Groq gpt-oss-20b (API) | `openai/gpt-oss-20b` | 0.955 | 0.972 | **0.963** | 0.954 | 5 | 3 | 5/31 | no failed batch* | 9 | 1.13 | 27.1 | $0.0033 | 0 | `groq_test.json` |
| rules + Gemini flash-lite (API) | `gemini-flash-lite-latest` | 0.991 | 0.991 | **0.991** | 0.963 | 1 | 1 | 1/31 | no failed batch* | 9 | 1.77 | 2.327 | $0.0023 | 0 | `gemini_test.json` |

\* API providers run in JSON mode (`response_format=json_object` / Gemini JSON); a batch counts as invalid only if it failed, and 0 lines failed in those runs.

## Per-category recall (detected / n)

| category | rules only | rules + Qwen2.5-0.5B base (local, no LoRA) | rules + Qwen2.5-0.5B QLoRA v1 data (local) | rules + Qwen2.5-0.5B QLoRA v2 data (local) | rules + Groq gpt-oss-20b (API) | rules + Gemini flash-lite (API) |
|---|---|---|---|---|---|---|
| ANOMALOUS_LOGIN | 0/2 | 0/2 | 2/2 | 0/2 | 2/2 | 2/2 |
| B64_PAYLOAD | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| BRUTE_FORCE | 22/23 | 22/23 | 23/23 | 23/23 | 23/23 | 23/23 |
| CMD_INJECTION | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| CRED_STUFFING | 0/12 | 0/12 | 8/12 | 7/12 | 12/12 | 12/12 |
| DATA_EXFIL | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| DEFENSE_EVASION | 0/2 | 0/2 | 2/2 | 0/2 | 2/2 | 2/2 |
| LOG4SHELL | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| PASSWORD_SPRAY | 0/5 | 0/5 | 5/5 | 0/5 | 5/5 | 5/5 |
| PATH_TRAVERSAL | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 |
| PERSISTENCE | 0/2 | 0/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| PRIV_ESC | 5/6 | 5/6 | 6/6 | 5/6 | 5/6 | 6/6 |
| PROMPT_INJECTION | 1/3 | 1/3 | 3/3 | 1/3 | 3/3 | 3/3 |
| RECON | 5/15 | 5/15 | 10/15 | 5/15 | 14/15 | 15/15 |
| SQLI | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 |
| SSRF | 7/7 | 7/7 | 7/7 | 7/7 | 7/7 | 7/7 |
| WEBSHELL | 0/2 | 0/2 | 1/2 | 0/2 | 2/2 | 2/2 |
| XSS | 5/6 | 5/6 | 5/6 | 5/6 | 5/6 | 5/6 |
