# Resume lines (numbers only from VERIFY.md)

- Built an eval harness for ThreatLens (rules + LLM log-threat detector): 371-line labelled golden set with dev/test split, per-category P/R/F1; held-out F1 rose 0.973→0.991 after dev-only fixes.
- Calibrated a Gemini LLM-as-judge against 90 hand-labelled explanations, raising held-out agreement from κ 0.29 to 0.75; added Langfuse tracing, Promptfoo regressions, and cached-replay CI eval gates.

Keywords this project now proves: LLM evaluation, golden datasets, precision/recall/F1, error analysis,
LLM-as-judge, Cohen's kappa, prompt engineering, prompt-injection testing, Promptfoo, Langfuse /
OpenTelemetry tracing, eval-gated CI (GitHub Actions), response caching, Gemini, Groq.

Caveats to say in an interview: synthetic logs, agent-produced (single-annotator) labels, single-sample
LLM runs; Groq's held-out F1 did not improve (0.968→0.963); CI workflow written and run locally, not on GitHub.
