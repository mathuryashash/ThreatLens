# Rule Engine Specification — ThreatLens

## Design Principles

- Rules run on a **normalized copy** of `raw_content` — URL-decoded, HTML-decoded, lowercased
- `raw_content` is **never modified**
- Rules run **before** the Groq classifier — logs matched by rules do not go to AI
- Every rule insert checks **duplicate suppression** first
- Rules are deterministic and produce `classification_source='rule'`

---

## Input Normalization

```python
def normalize_for_matching(text: str) -> str:
    from urllib.parse import unquote
    import html
    return html.unescape(unquote(text)).lower()
```

This handles:
- Standard URL encoding: `%2e%2e%2f` → `../`
- Double encoding: `%252e` → `%2e` → `.` (apply unquote twice if needed)
- HTML entity encoding: `&lt;script&gt;` → `<script>`
- Mixed case: `UNION SELECT` → `union select`

Normalization runs on the raw content before any pattern matching. The normalized string is never stored — it is only used in-memory for matching.

---

## Pattern Rules

### SQLI — SQL Injection
**Severity**: HIGH | **Score**: 80 | **Confidence**: 0.90

Patterns (applied to normalized text):
```python
SQLI_PATTERNS = [
    r'\bunion\s+select\b',           # UNION SELECT
    r'\bor\s+1\s*=\s*1\b',          # OR 1=1
    r"'\s+or\s+'1'\s*=\s*'1",       # ' OR '1'='1
    r'\bsleep\s*\(',                 # sleep() blind injection
    r'\bbenchmark\s*\(',             # benchmark() blind injection
    r'\binformation_schema\b',       # schema enumeration
    r'\bdrop\s+table\b',             # DROP TABLE
]
```

**NOT included**: `--` alone (too many false positives — SQL comments appear in legitimate log data).

### XSS — Cross-Site Scripting
**Severity**: MEDIUM | **Score**: 65 | **Confidence**: 0.85

Patterns (applied to normalized text — normalization handles encoded variants):
```python
XSS_PATTERNS = [
    r'<script[\s>]',                 # <script> tag
    r'javascript:',                  # javascript: URI
    r'onerror\s*=',                  # onerror event handler
    r'onload\s*=',                   # onload event handler
    r'<iframe[\s>]',                 # <iframe> tag
]
```

Normalization handles `%3cscript%3e` → `<script>` before matching.

### PATH_TRAVERSAL — Directory Traversal
**Severity**: MEDIUM | **Score**: 60 | **Confidence**: 0.88

Patterns (applied to normalized text — normalization handles double-encoding):
```python
PATH_TRAVERSAL_PATTERNS = [
    r'\.\./|\.\.\\',                 # ../ or ..\
    r'%252e%252e',                   # double-encoded ..
    r'\.\.%2f',                      # partially encoded
    r'etc/passwd',                   # direct target reference
    r'proc/self/environ',            # proc filesystem
    r'win\.ini',                     # Windows target
    r'boot\.ini',                    # Windows target
]
```

Double encoding `%252e%252e%252f` → after first decode: `%2e%2e%2f` → after second decode: `../`. The normalize function handles this.

### PRIV_ESC — Privilege Escalation
**Severity**: CRITICAL | **Score**: 90 | **Confidence**: 0.95

Patterns (applied to raw log text — these are structured auth log messages):
```python
PRIV_ESC_PATTERNS = [
    r'sudo:.*authentication failure',
    r'su:.*failed su',
    r'authentication failure for root',
]
```

### SSRF — Server-Side Request Forgery
**Severity**: CRITICAL | **Score**: 95 | **Confidence**: 0.98

Patterns (applied to normalized text):
```python
SSRF_PATTERNS = [
    r'169\.254\.169\.254',           # AWS/Azure metadata endpoint
    r'metadata\.google\.internal',  # GCP metadata endpoint
]
```

These patterns are extremely high-confidence — these IPs/hostnames appear in logs almost exclusively when SSRF is being attempted.

---

## Correlation Rules

Correlation rules group events across time and require state accumulation.

### BRUTE_FORCE
**Severity**: HIGH | **Score**: 75 | **Confidence**: 0.92

**Detection logic**: Group `parsed_events` by `source_ip` where `action='LOGIN_FAILED'`. If 10+ events from the same IP within a 5-minute rolling window → BRUTE_FORCE.

```python
from datetime import datetime, timedelta
from collections import defaultdict

def detect_brute_force(parsed_events: list, window_minutes=5, threshold=10) -> list[dict]:
    by_ip = defaultdict(list)
    for event in parsed_events:
        if event.action == 'LOGIN_FAILED' and event.source_ip:
            by_ip[str(event.source_ip)].append(event.timestamp)

    threats = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        for i, ts in enumerate(timestamps):
            window_end = ts + timedelta(minutes=window_minutes)
            count = sum(1 for t in timestamps[i:] if t <= window_end)
            if count >= threshold:
                threats.append({"source_ip": ip, "count": count})
                break  # one threat per IP per detection pass
    return threats
```

### PORT_SCAN (stretch — implement only if time allows)
**Severity**: MEDIUM | **Score**: 55 | **Confidence**: 0.70

**Detection logic**: Same `source_ip`, 15+ distinct destination ports touched in any order.

---

## Severity Mapping

| Rule | Severity | Score | Rationale |
|------|----------|-------|-----------|
| SSRF | CRITICAL | 95 | Direct cloud credential exposure risk |
| PRIV_ESC | CRITICAL | 90 | Root access attempt |
| SQLI | HIGH | 80 | Data exfiltration risk |
| BRUTE_FORCE | HIGH | 75 | Credential compromise risk |
| XSS | MEDIUM | 65 | Requires victim interaction; server-logged XSS is less severe |
| PATH_TRAVERSAL | MEDIUM | 60 | Usually blocked; severity if successful is high |
| PORT_SCAN | MEDIUM | 55 | Reconnaissance activity |

---

## Duplicate Suppression

Before every rule-based `INSERT` into `threats`:

```python
async def is_duplicate_threat(
    session_id: str,
    threat_type: str,
    source_ip: str | None,
    window_minutes: int = 5
) -> bool:
    result = supabase.table("threats").select("id").match({
        "session_id": session_id,
        "threat_type": threat_type,
        "source_ip": source_ip,
    }).gte(
        "detected_at",
        (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
    ).limit(1).execute()
    return len(result.data) > 0
```

If duplicate: skip insert, continue processing. Do not log as an error.

---

## Known False Positives

| Pattern | False Positive Scenario |
|---------|------------------------|
| `or 1=1` | Legitimate text in application logs ("error or 1=1 condition in config") |
| `information_schema` | Legitimate DBA queries in application logs |
| `../` | Log lines from build systems, package managers |
| `<script>` | HTML in application error logs, email templates |
| BRUTE_FORCE | Monitoring systems making repeated health check logins |

**Mitigation**: Rules use word boundaries (`\b`) where possible. Normalization handles encoding variants without over-matching. The `--` pattern was explicitly excluded due to excessive false positives.

---

## Known False Negatives

| Scenario | Why missed |
|----------|-----------|
| Novel SQLi technique not in pattern set | Rules only match known patterns — Groq handles novel cases |
| XSS via CSS expression | Pattern set focuses on common vectors |
| SSRF to private RFC 1918 addresses | Only cloud metadata IPs are in pattern set (private IPs are common in logs) |
| Slow brute force (1 attempt/hour) | Window-based correlation only catches bursts |
| Encoded PRIV_ESC log lines | Auth log patterns match structured syslog format; heavily mangled input may miss |

False negatives in rules are the primary reason the Groq classifier exists.

---

## classification_source Values

| Value | Meaning |
|-------|---------|
| `rule` | Matched by deterministic rule — no Groq call made |
| `ai` | No rule match — classified by Groq |
| `hybrid` | POST-MVP only — rule detected + AI enriched. **Do not implement in Phase 1–3.** |
