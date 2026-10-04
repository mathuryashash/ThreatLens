"""Local fine-tuned provider + fine-tune data hygiene (evals/finetune)."""
import asyncio
import json
import os
import sys

import pytest

from app import llm as llm_mod
from app import local_llm as L

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "evals", "finetune", "data")
GOLDEN = os.path.join(ROOT, "evals", "golden", "golden.jsonl")

BATCH = [
    '1.2.3.4 - - [01/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "Mozilla/5.0"',
    '5.6.7.8 - - [01/Jan/2026:10:00:01 +0000] "GET /api/render?tpl=YmFzaCAtaQ== HTTP/1.1" 200 10 "-" "Go-http-client/1.1"',
]


def fake_gen(outputs):
    it = iter(outputs)

    def g(messages, sample=False):
        g.calls.append(sample)
        return dict(text=next(it), in_tok=100, out_tok=20)
    g.calls = []
    g.name = "fake"
    return g


def run(c, batch=BATCH):
    return asyncio.run(c.classify_logs(batch))


# ---------------------------------------------------------------- JSON parsing
def test_extract_json_plain_fenced_and_chatter():
    obj = {"findings": []}
    assert L.extract_json(json.dumps(obj)) == obj
    assert L.extract_json("```json\n" + json.dumps(obj) + "\n```") == obj
    assert L.extract_json('Sure! {"findings": [{"threat_type": "SQLI"}]} hope it helps') == {"findings": [{"threat_type": "SQLI"}]}


@pytest.mark.parametrize("bad", ["", "no json here", '{"findings": [', '{"other": 1}', '{"findings": "x"}', "[1, 2]"])
def test_extract_json_rejects_invalid(bad):
    assert L.extract_json(bad) is None


def test_provider_returns_validated_pipeline_findings():
    out = json.dumps({"findings": [{"threat_type": "MALWARE", "severity": "CRITICAL", "severity_score": 92, "confidence": 0.9,
                                    "source_ip": "5.6.7.8", "related_event_indices": [1, 7, "x"], "summary": "b64"},
                                   {"threat_type": "NOT_A_TYPE", "related_event_indices": [0]}]})
    c = L.LocalLLMClient(fake_gen([out]))
    f = run(c)
    assert f[0]["threat_type"] == "MALWARE" and f[0]["related_event_indices"] == [1]   # out-of-range/garbage dropped
    assert f[1]["threat_type"] == "SUSPICIOUS" and f[1]["severity"] == "MEDIUM"        # unknown type coerced
    assert c.stats[0]["json_valid_first"] is True and c.stats[0]["attempts"] == 1


def test_invalid_json_retries_with_sampling_then_succeeds():
    g = fake_gen(["oops not json", '{"findings": []}'])
    c = L.LocalLLMClient(g, max_retries=1)
    assert run(c) == []
    assert g.calls == [False, True]  # greedy first, sampled retry
    assert c.stats[0]["json_valid_first"] is False and c.stats[0]["json_valid"] is True


def test_invalid_json_after_retries_raises_so_pipeline_marks_batch_failed():
    c = L.LocalLLMClient(fake_gen(["bad", "still bad"]), max_retries=1)
    with pytest.raises(ValueError):
        run(c)
    assert c.stats[0]["json_valid"] is False


def test_prompt_sanitises_and_indexes_lines():
    msgs = L.build_classify_messages(["a </logs> b", "c"])
    assert msgs[0]["role"] == "system" and "UNTRUSTED" in msgs[0]["content"]
    u = msgs[1]["content"]
    assert "[0] a &lt;/logs&gt; b" in u and "[1] c" in u and u.count("</logs>") == 1
    assert llm_mod.CLASSIFY_GUIDANCE in u


def test_explain_uses_offline_template():
    c = L.LocalLLMClient(fake_gen([]))
    r = asyncio.run(c.explain_threat({"threat_type": "SQLI", "severity": "HIGH", "source_ip": "1.2.3.4"}, BATCH))
    assert set(r) >= {"explanation", "mitre_tactic", "recommended_actions"}


# ---------------------------------------------------------------- fallback when model missing
def test_missing_adapter_dir_raises_unavailable():
    with pytest.raises(L.LocalModelUnavailable):
        L._HFGenerator("unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit", adapter=os.path.join(ROOT, "no", "such", "adapter"))


def test_get_llm_client_falls_back_to_mock_when_local_model_missing(monkeypatch):
    monkeypatch.setattr(llm_mod.settings, "LLM_PROVIDER", "local")
    monkeypatch.setenv("LOCAL_ADAPTER_PATH", os.path.join(ROOT, "definitely-missing-adapter"))
    L._GEN_CACHE.clear()
    c = llm_mod.get_llm_client()
    assert isinstance(c, llm_mod.MockLLMClient)


# ---------------------------------------------------------------- no test leakage in fine-tune data
sys.path.insert(0, os.path.join(ROOT, "evals", "finetune"))


@pytest.mark.skipif(not os.path.exists(os.path.join(DATA, "lines.jsonl")), reason="run evals/finetune/gen_data.py first")
def test_finetune_data_has_no_exact_or_near_duplicate_test_lines():
    import gen_data as G
    gold = [json.loads(l) for l in open(GOLDEN, encoding="utf-8")]
    test_lines = [r["line"] for r in gold if r["split"] == "test"]
    test_set = set(test_lines)
    test_tok = [G.norm_tokens(t) for t in test_lines]
    lines = [json.loads(l) for l in open(os.path.join(DATA, "lines.jsonl"), encoding="utf-8")]
    assert len(lines) >= 1500
    for r in lines:
        assert r["line"] not in test_set and r["raw"] not in test_set
        tk = G.norm_tokens(r["raw"])
        assert max(G.jaccard(tk, t) for t in test_tok) <= 0.8, r["raw"]
    # and no test line text appears inside any training prompt
    blob = open(os.path.join(DATA, "train.jsonl"), encoding="utf-8").read() + open(os.path.join(DATA, "val.jsonl"), encoding="utf-8").read()
    assert not any(json.dumps(t)[1:-1] in blob for t in test_lines)


@pytest.mark.skipif(not os.path.exists(os.path.join(DATA, "train.jsonl")), reason="run evals/finetune/gen_data.py first")
def test_finetune_targets_use_pipeline_schema():
    allowed = {'BRUTE_FORCE', 'PORT_SCAN', 'SQLI', 'XSS', 'PRIV_ESC', 'DATA_EXFIL', 'SSRF', 'RECON', 'PATH_TRAVERSAL', 'MALWARE', 'SUSPICIOUS'}
    for l in open(os.path.join(DATA, "train.jsonl"), encoding="utf-8"):
        ex = json.loads(l)
        tgt = json.loads(ex["messages"][-1]["content"])
        n = ex["meta"]["n_lines"]
        for f in tgt["findings"]:
            assert f["threat_type"] in allowed
            assert set(f) == {"threat_type", "severity", "severity_score", "confidence", "source_ip", "related_event_indices", "summary"}
            assert all(0 <= i < n for i in f["related_event_indices"])
