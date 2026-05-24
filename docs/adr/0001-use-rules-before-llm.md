# ADR 0001 — Run Rule Engine Before LLM Classifier

**Status**: Accepted

## Context

We need to classify log lines as threats or benign. Two options: pure LLM classification, or a hybrid approach where deterministic rules run first.

Key constraints:
- Groq free tier has rate limits (~30 RPM)
- LLM latency is 1–3 seconds per call
- Some attack patterns (SQLi, SSRF, path traversal) are deterministically identifiable
- False negatives on obvious attacks (SQL injection in logs) are unacceptable

## Decision

Run the deterministic rule engine first. Only logs that do not match any rule are sent to Groq for classification.

Rule-matched threats get `classification_source='rule'`. AI-classified threats get `classification_source='ai'`.

## Alternatives Considered

**Pure LLM classification**: All logs go to Groq. Simpler code, but: higher latency, higher cost, rate limit risk, and LLM can produce false positives/negatives on patterns that rules would catch with 100% accuracy.

**Pure rules**: No AI. Faster, fully deterministic, but produces no human-readable explanations and misses novel or ambiguous attack patterns.

## Consequences

- Obvious attacks are detected instantly and reliably
- Groq call volume is minimized (only ambiguous logs go to AI)
- The system degrades gracefully if Groq is unavailable (rule-matched threats still appear)
- Explain button is independent of classification — any threat can be explained by AI regardless of how it was classified
- Answer to "why LLM instead of grep?": "Rules handle what we know. AI explains it and handles what we don't know."
