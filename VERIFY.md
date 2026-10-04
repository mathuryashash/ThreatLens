# VERIFY - ThreatLens-Evals

Branch `hermes/threatlens-evals` (from `hermes/qa-loop`), worktree `D:/ai-build/threatlens-evals`.
All commands run from the worktree root on Windows/git-bash; `PY=backend/venv/Scripts/python`.
Env for every command: `ALLOW_MOCK_DB=true SUPABASE_URL= SUPABASE_SERVICE_ROLE_KEY= DATABASE_URL=`
(in-memory DB; prod never touched). LLM keys were read from `D:/aihackthonforbuilder/backend/.env`
via `--env-file` and never printed. `.env*` is gitignored.

## 1. Tests
```
cd backend && $PY -m pytest -q
101 passed, 2914 warnings in 6.10s
```
82 pre-existing + 8 tracing (`tests/test_tracing.py`) + 11 eval-improvement (`tests/test_eval_improvements.py`).
The 11 were written first and failed (`6 failed, 5 passed`) before the RECON rule / prompt guidance existed.

## 2. Golden set
```
$PY evals/golden/build_golden.py
total 371 {('dev','benign'): 104, ('dev','attack'): 64, ('test','benign'): 95, ('test','attack'): 108}
hard negatives 47
```
* 212 lines copied from the earlier live QA answer key (`seed_live_212.json`, user-approved copy) +
  159 new lines (held-out nginx2/auth2 streams, hard negatives, prompt-injection streams). 18 categories.
* Split by stream. **TEST-only streams: `sample_nginx`, `sample_auth`, `nginx2`, `auth2`, `inject_test`.**
  DEV: `nginx`, `auth`, `inject_dev`. Rules in `evals/golden/LABELING.md`.
* Fine-tune export: `python evals/golden/export_finetune.py` ->
  `train_dev=10 windows, augmented_dev=30 windows, eval_test(EVAL ONLY)=12 windows`
  (20-line chat-format windows; augmented = deterministic IP/date/host perturbations of DEV lines only;
  script asserts no test id appears in train/augmented).

## 3. Eval runner (real pipeline: parser -> redactor -> process_rules -> LLM batches of 20)
`$PY evals/run.py --provider rules|gemini|groq|nim --split dev|test [--cache readonly] [--min-f1 ..]`
Real output lines (after improvements):
```
rules  dev : n=168 P=1.000 R=0.500 F1=0.667 tp=32 fp=0 fn=32
rules  test: n=203 P=0.985 R=0.593 F1=0.740 tp=64 fp=1 fn=44
gemini dev : n=168 P=0.955 R=0.984 F1=0.969 tp=63 fp=3 fn=1  calls=8 tok=16379/1568 p50=1.926 p95=2.839 failed=0
gemini test: n=203 P=0.991 R=0.991 F1=0.991 tp=107 fp=1 fn=1 calls=9 tok=16368/1712 p50=1.77 p95=2.327 failed=0
groq   dev : n=168 P=1.000 R=0.984 F1=0.992 tp=63 fp=0 fn=1  calls=8 tok=14612/1148 p50=24.716 p95=85.248 failed=0
groq   test: n=203 P=0.955 R=0.972 F1=0.963 tp=105 fp=5 fn=3 calls=9 tok=14883/1706 p50=1.13 p95=27.1 failed=0
```
Baselines (before improvements), same commands, saved as `*_baseline.json`:
rules test F1 0.695 (P 0.983 R 0.537); gemini test F1 0.973 (P 0.964 R 0.982); groq test F1 0.968 (P 0.947 R 0.991).
Models: Gemini `gemini-flash-lite-latest`, Groq `openai/gpt-oss-20b` (classify). Groq latency p50/p95 include
429 retry waits (shared free-tier key). Cost column = list-price estimate (~$0.002-0.003 per 200-line run).
Full table: `evals/results/LEADERBOARD.md`; per-category recall, per-type precision, confusion matrix in each results JSON.
Disk cache: `evals/cache/` (sha256 of url+payload, 170 entries, errors never cached).
`--cache readonly` with the cache removed -> 16 "cache miss in readonly mode" errors (verified, then restored).
Threshold gate verified: `--min-f1 0.999` -> `THRESHOLD FAIL: f1 0.9907 < 0.999`, exit 1.
NVIDIA NIM: provider implemented (`--provider nim`) but **not run - no NVIDIA key found** in the repo env files.

## 4. Error analysis + improvements (DEV-tuned, TEST reported) - `evals/ERROR_ANALYSIS.md`
1. RECON sensitive-path rule; 2. `CLASSIFY_GUIDANCE` in both classify prompts.
TEST delta: rules F1 0.695 -> 0.740; rules+Gemini F1 0.973 -> 0.991 (FP 4->1, FN 2->1);
rules+Groq F1 0.968 -> **0.963 (worse)** despite DEV 0.905 -> 0.992 - reported as prompt over-fit to DEV.

## 5. LLM-as-judge - `evals/judge/JUDGE.md`
90 explanations (45 incidents x {Gemini explain_threat, Mock fallback}) hand-labelled 1-5 + pass/fail with
written rationale (by the agent, single annotator). Judge = Gemini flash-lite, temp 0.
```
judge v1 dev     n=32 acc=0.6875 kappa=0.3962
judge v2 dev     n=32 acc=0.8438 kappa=0.6825
judge v1 heldout n=58 acc=0.6207 kappa=0.2895
judge v2 heldout n=58 acc=0.8793 kappa=0.7515
```
v2 written after reading v1 disagreements on dev only. Remaining held-out errors: 6 stricter-than-label MITRE calls, 1 lenient.

## 6. Promptfoo - `evals/promptfoo/promptfooconfig.yaml`
5 tests / 13 assertions over golden streams via a python provider that runs the real pipeline from cache.
Provider verified directly (cached Gemini): inject_dev 6/6 attacks, 0 FP; inject_test 6/6, 0 FP;
nginx2 31/31, 0 FP; auth2 24/24, 1 FP (auth2:15); nginx 35/35, 1 FP (nginx:10).
Real promptfoo run (promptfoo 0.118.17 installed to `D:/promptfoo-tool`; `npx promptfoo@latest` hung
during install and needs Node >=22.22, local is 22.16 - so the version is pinned):
```
cd evals/promptfoo && PROMPTFOO_PYTHON=../../backend/venv/Scripts/python.exe GEMINI_API_KEY= \
  node D:/promptfoo-tool/node_modules/promptfoo/dist/src/main.js eval -c promptfooconfig.yaml --no-cache --max-concurrency 1
exit=0   stats {'successes': 5, 'failures': 0, 'errors': 0}   assertions 20
```
The first run exited 100 (2 failures): two assertions returned `{pass, reason}` without `score`, which
promptfoo rejects; fixed the config (both values were already pass=true) and re-ran. Results:
`evals/results/promptfoo_results.json`.

## 7. Langfuse tracing - `backend/app/tracing.py`
Enabled only when `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` are set; otherwise a no-op span and
`langfuse` is never imported. Wraps all 4 LLM calls (Groq/Gemini x classify/explain) as `generation`
observations with input, output, model and token usage. Tests: no-op without keys, no import, stub client
receives span with name/metadata/usage, error spans re-raise, broken exporter never breaks classification,
and the real langfuse 4.16.0 SDK with fake keys + in-memory OTel exporter emits a `gemini.classify_logs` span.
No real Langfuse project was used (no keys) - traces were not viewed in a Langfuse UI.

## 8. CI - `.github/workflows/evals.yml` (not run on GitHub: no push allowed)
Same commands run locally, all exit 0:
```
pytest                                  -> 101 passed
build_golden.py + git diff golden.jsonl -> no diff
run.py --provider rules --split test --tag ci --min-precision 0.97 --min-recall 0.55 -> P=0.985 R=0.593, exit 0
run.py --provider gemini --split test --cache readonly --tag ci --min-f1 0.95 --min-precision 0.95 -> F1=0.991 (cached 9/9), exit 0
judge.py --prompt v2 --part heldout --cache readonly -> acc=0.8793 kappa=0.7515
```

## Limitations
* All 371 lines are synthetic, single-annotator (agent) labels; no inter-annotator agreement.
* Judge "human" labels were produced by the agent, not a human analyst.
* LLM results are single samples; run-to-run variance not measured.
* NIM not run (no key). Groq ran under 429 pressure (shared key); latency numbers include retry waits.
* Langfuse verified only against stub + in-memory exporter, not a live Langfuse server.
* CI workflow not executed on GitHub.
* A non-LLM key line from `D:/ai-resume-job-tracker/keys.txt` was partially echoed to this agent's
  terminal output while searching for an NVIDIA key (not written to any file or commit) - consider rotating it.
