"""Env-gated Langfuse tracing: no-op without keys; spans produced against a stub client."""
import asyncio
import json
from contextlib import contextmanager

import httpx
import pytest

from app import tracing
from app import llm as llm_mod


class StubSpan:
    def __init__(self, rec):
        self.rec = rec

    def update(self, **kw):
        self.rec["updates"].append(kw)


class StubLangfuse:
    def __init__(self):
        self.spans = []

    @contextmanager
    def start_as_current_observation(self, **kw):
        rec = dict(start=kw, updates=[], exc=None)
        self.spans.append(rec)
        try:
            yield StubSpan(rec)
        except BaseException as e:
            rec["exc"] = type(e).__name__
            raise


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    tracing.set_client(None)
    yield
    tracing.set_client(None)


def _gemini_response(findings):
    body = {"candidates": [{"content": {"parts": [{"text": json.dumps({"findings": findings})}]}}],
            "usageMetadata": {"promptTokenCount": 120, "candidatesTokenCount": 30}}
    return httpx.Response(200, json=body, request=httpx.Request("POST", "https://x"))


def _patch_post(monkeypatch, resp):
    async def fake_post(client, url, **kw):
        return resp
    monkeypatch.setattr(llm_mod, "_post_with_retry", fake_post)


def test_disabled_without_keys(monkeypatch):
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    assert tracing.is_enabled() is False
    with tracing.llm_span("x") as span:
        assert span is tracing.NOOP_SPAN
        span.update(output="ignored")  # must not raise


def test_noop_does_not_import_langfuse(monkeypatch):
    import sys
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    monkeypatch.setitem(sys.modules, "langfuse", None)  # any import attempt would raise ImportError
    with tracing.llm_span("x") as span:
        assert span is tracing.NOOP_SPAN


def test_classify_unchanged_when_disabled(monkeypatch):
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    f = [{"threat_type": "SQLI", "severity": "HIGH", "severity_score": 80, "confidence": 0.9,
          "source_ip": "1.2.3.4", "related_event_indices": [0], "summary": "sqli"}]
    _patch_post(monkeypatch, _gemini_response(f))
    out = asyncio.run(llm_mod.GeminiClient().classify_logs(["line a"]))
    assert out[0]["threat_type"] == "SQLI"


def test_spans_produced_against_stub(monkeypatch):
    stub = StubLangfuse()
    tracing.set_client(stub)
    f = [{"threat_type": "XSS", "severity": "MEDIUM", "severity_score": 60, "confidence": 0.8,
          "source_ip": None, "related_event_indices": [1], "summary": "xss"}]
    _patch_post(monkeypatch, _gemini_response(f))
    out = asyncio.run(llm_mod.GeminiClient().classify_logs(["a", "b"]))
    assert out[0]["threat_type"] == "XSS"
    assert len(stub.spans) == 1
    s = stub.spans[0]
    assert s["start"]["name"] == "gemini.classify_logs"
    assert s["start"]["as_type"] == "generation"
    assert s["start"]["metadata"] == {"batch_size": 2}
    assert "<logs>" in s["start"]["input"]
    upd = s["updates"][-1]
    assert upd["usage_details"] == {"input": 120, "output": 30}
    assert upd["output"]["findings"][0]["threat_type"] == "XSS"


def test_span_records_error_and_reraises(monkeypatch):
    stub = StubLangfuse()
    tracing.set_client(stub)
    _patch_post(monkeypatch, httpx.Response(503, json={}, request=httpx.Request("POST", "https://x")))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(llm_mod.GeminiClient().classify_logs(["a"]))
    assert stub.spans[0]["exc"] == "HTTPStatusError"
    assert stub.spans[0]["updates"][0]["level"] == "ERROR"


def test_groq_explain_span(monkeypatch):
    stub = StubLangfuse()
    tracing.set_client(stub)
    body = {"choices": [{"message": {"content": json.dumps({"explanation": "e", "mitre_tactic": "Initial Access",
                                                             "recommended_actions": ["a"]})}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 10}}
    _patch_post(monkeypatch, httpx.Response(200, json=body, request=httpx.Request("POST", "https://x")))
    r = asyncio.run(llm_mod.GroqClient().explain_threat({"threat_type": "SQLI"}, ["l"]))
    assert r["mitre_tactic"] == "Initial Access"
    assert stub.spans[0]["start"]["name"] == "groq.explain_threat"
    assert stub.spans[0]["updates"][-1]["usage_details"] == {"input": 50, "output": 10}


def test_broken_client_never_breaks_classification(monkeypatch):
    class Broken:
        def start_as_current_observation(self, **kw):
            raise RuntimeError("exporter down")
    tracing.set_client(Broken())
    _patch_post(monkeypatch, _gemini_response([]))
    assert asyncio.run(llm_mod.GeminiClient().classify_logs(["a"])) == []


def test_real_langfuse_sdk_with_fake_keys_produces_span(monkeypatch):
    """Real langfuse SDK + OTel in-memory exporter: our wrapper emits a real generation span."""
    lf = pytest.importorskip("langfuse")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exporter = InMemorySpanExporter()
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(exporter))
    client = lf.Langfuse(public_key="pk-lf-test", secret_key="sk-lf-test", host="http://127.0.0.1:9",
                         tracer_provider=tp, tracing_enabled=True)
    tracing.set_client(client)
    with tracing.llm_span("gemini.classify_logs", model="m", input="p") as span:
        span.update(output={"findings": []})
    tp.force_flush()
    names = [s.name for s in exporter.get_finished_spans()]
    assert "gemini.classify_logs" in names
