# Resume lines (fine-tune; numbers only from VERIFY.md)

- QLoRA-fine-tuned Qwen2.5-0.5B (4-bit, r=16) on an 8 GB laptop GPU in 752.8 s on 478 synthetic log windows with 0 test-set overlap; 9/9 valid-JSON test batches, $0/call offline.
- Benchmarked it honestly on a held-out set: F1 0.748 vs 0.740 rules-only, 0.963 Groq gpt-oss-20b and 0.991 Gemini; documented where small on-device models lose.

Keywords this adds: QLoRA, LoRA/PEFT, bitsandbytes 4-bit, TRL SFT, synthetic data generation, train/test
leakage control, local/on-device inference, model card, cost/latency/quality trade-off analysis.

Caveat to say in an interview: the fine-tune did NOT beat the API models. It was +0.008 F1 over rules-only on 203 test lines, from a single run.

---

# Resume lines (numbers only from VERIFY.md)

- Built an eval harness for ThreatLens (rules + LLM log-threat detector): 371-line labelled golden set with dev/test split, per-category P/R/F1; held-out F1 rose 0.973→0.991 after dev-only fixes.
- Calibrated a Gemini LLM-as-judge against 90 hand-labelled explanations, raising held-out agreement from κ 0.29 to 0.75; added Langfuse tracing, Promptfoo regressions, and cached-replay CI eval gates.

Keywords this project now proves: LLM evaluation, golden datasets, precision/recall/F1, error analysis,
LLM-as-judge, Cohen's kappa, prompt engineering, prompt-injection testing, Promptfoo, Langfuse /
OpenTelemetry tracing, eval-gated CI (GitHub Actions), response caching, Gemini, Groq.

Caveats to say in an interview: synthetic logs, agent-produced (single-annotator) labels, single-sample
LLM runs; Groq's held-out F1 did not improve (0.968→0.963); CI workflow written and run locally, not on GitHub.
