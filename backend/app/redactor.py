import re

REDACTION_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[AWS_KEY]'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), '[GITHUB_TOKEN]'),
    (re.compile(r'ghs_[a-zA-Z0-9]{36}'), '[GITHUB_TOKEN]'),
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '[JWT]'),
    (re.compile(r'(?i)authorization:\s*bearer\s+\S+'), 'Authorization: Bearer [REDACTED]'),
    (re.compile(r'(?i)authorization:\s*basic\s+\S+'), 'Authorization: Basic [REDACTED]'),
    (re.compile(r'(?i)password\s*[=:]\s*\S+'), 'password=[REDACTED]'),
    (re.compile(r'(?i)(access_token|refresh_token|client_secret|api_key|token|secret)\s*=\s*([^&\s]+)'), lambda m: f'{m.group(1)}=[REDACTED]'),
    (re.compile(r'(?i)cookie:\s*.+'), 'Cookie: [REDACTED]'),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[EMAIL]'),
    (re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC |DSA |)?PRIVATE KEY-----'), '[SSH_PRIVATE_KEY]'),
    (re.compile(r'sk_live_[A-Za-z0-9]{24,}'), '[STRIPE_KEY]'),
    (re.compile(r'sk_test_[A-Za-z0-9]{24,}'), '[STRIPE_KEY]'),
    (re.compile(r'xox[baprs]-[0-9A-Za-z\-]+'), '[SLACK_TOKEN]'),
    (re.compile(r'"private_key_id"\s*:\s*"[^"]{10,}"'), '"private_key_id": "[REDACTED]"'),
    (re.compile(r'(?i)(priv|auth|credential|passwd|appkey|app_key|app_secret)\s*=\s*([^&\s]{6,})'), lambda m: f'{m.group(1)}=[REDACTED]'),
]

def redact_content(text: str) -> str:
    if not text:
        return ""

    from urllib.parse import unquote
    import html as _html

    def _apply_patterns(s: str) -> str:
        for pattern, replacement in REDACTION_PATTERNS:
            if callable(replacement):
                s = pattern.sub(replacement, s)
            else:
                s = pattern.sub(replacement, s)
        return s

    redacted = _apply_patterns(text)

    # Also catch URL-encoded secrets by redacting the decoded form
    try:
        decoded = _html.unescape(unquote(unquote(text)))
        if decoded != text:
            redacted_decoded = _apply_patterns(decoded)
            if redacted_decoded != decoded:
                # Re-apply patterns to the original redacted output to catch anything missed
                redacted = _apply_patterns(redacted)
    except Exception:
        pass

    return redacted
