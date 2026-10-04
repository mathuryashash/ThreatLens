"""Eval-driven improvements (tuned on the DEV split only; see evals/ERROR_ANALYSIS.md)."""
import pytest

from app.rules import check_pattern_rules
from app import llm as llm_mod

# DEV-split recon misses (nginx:94-98)
RECON_HITS = [
    '45.9.148.201 - - [24/May/2026:09:50:01 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 zgrab/0.x"',
    '45.9.148.201 - - [24/May/2026:09:50:02 +0000] "GET /.git/HEAD HTTP/1.1" 404 162 "-" "Mozilla/5.0 zgrab/0.x"',
    '45.9.148.201 - - [24/May/2026:09:50:03 +0000] "GET /actuator/heapdump HTTP/1.1" 404 162 "-" "x"',
    '45.9.148.201 - - [24/May/2026:09:50:04 +0000] "GET /server-status HTTP/1.1" 404 162 "-" "x"',
    '45.9.148.201 - - [24/May/2026:09:50:05 +0000] "GET /.aws/credentials HTTP/1.1" 404 162 "-" "x"',
]
BENIGN = [
    '10.0.0.5 - - [24/May/2026:09:00:00 +0000] "GET /blog/how-to-use-dotenv-files HTTP/1.1" 200 9000 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [24/May/2026:09:00:00 +0000] "GET /assets/environment.js HTTP/1.1" 200 9000 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [24/May/2026:09:00:00 +0000] "GET /docs/git-workflow HTTP/1.1" 200 9000 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [24/May/2026:09:00:00 +0000] "GET /api/v2/healthz HTTP/1.1" 200 15 "-" "UptimeRobot/2.0"',
    '10.0.0.5 - - [24/May/2026:09:00:00 +0000] "GET /status HTTP/1.1" 200 15 "-" "Mozilla/5.0"',
]


@pytest.mark.parametrize("line", RECON_HITS)
def test_sensitive_file_probe_is_recon(line):
    m = check_pattern_rules(line)
    assert m is not None and m[0] == "RECON"


@pytest.mark.parametrize("line", BENIGN)
def test_lookalike_paths_are_not_flagged(line):
    assert check_pattern_rules(line) is None


def test_classify_guidance_in_both_provider_prompts():
    g = llm_mod.CLASSIFY_GUIDANCE
    assert "related_event_indices" in g and "prompt-injection" in g
    import inspect
    assert "CLASSIFY_GUIDANCE" in inspect.getsource(llm_mod.GroqClient.classify_logs)
    assert "CLASSIFY_GUIDANCE" in inspect.getsource(llm_mod.GeminiClient.classify_logs)
