# ADR 0003 — Preserve Raw Logs; Redact Only for LLM

**Status**: Accepted

## Context

Logs may contain sensitive values (API keys, JWTs, passwords) that should not be sent to a third-party LLM API. But the rule engine needs access to original content for accurate pattern matching, and audit integrity requires the original log to be preserved.

## Decision

Store `raw_content` immutably at insert time. Create a `redacted_content` copy after parsing. The rule engine runs on a normalized copy of `raw_content`. The Groq API receives `redacted_content` only.

- `raw_content`: never modified after INSERT
- `redacted_content`: best-effort secret stripping; used exclusively for LLM calls
- Rule engine: `normalize_for_matching(raw_content)` — in-memory only, not stored

## Alternatives Considered

**Redact before storage**: Store only redacted content. Simpler, but destroys evidence and makes it impossible to reprocess with improved redaction rules later.

**Send raw content to LLM**: Simpler pipeline, but risks leaking real secrets (AWS keys, tokens) to a third-party API.

**No redaction**: All content sent to Groq as-is. Unacceptable — users may have real secrets in their logs.

## Consequences

- Original log content is preserved for forensic and audit purposes
- LLM never sees unredacted secrets
- Rule engine matches against real content (before redaction strips patterns that rules depend on)
- If redaction patterns are improved, `raw_content` can be re-redacted (raw is immutable; redacted is regenerable)
- Limitation: redaction is best-effort — users are warned not to upload logs with real production secrets
