"""Minimal on-prem serving endpoint for the fine-tuned ThreatLens classifier (FastAPI + transformers).

  LOCAL_ADAPTER_PATH=evals/finetune/runs/<run>/adapter \
  python -m uvicorn serve_local:app --app-dir evals/finetune --port 8077

POST /classify {"lines": ["<raw log line>", ...]}  (<= 20 lines, same as one pipeline batch)
  -> {"findings": [...pipeline schema...], "latency_s": float, "model": str}
GET  /health -> {"status": "ok", "model": str}

The model is loaded once at startup and batches are serialised on the single GPU.
vLLM would be the Linux production path (continuous batching, paged KV cache); it does not run
natively on Windows, so this endpoint uses transformers generate() and was the one measured.
"""
import os
import sys
import time
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "backend"))
os.environ.setdefault("ALLOW_MOCK_DB", "true")

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from app.local_llm import LocalLLMClient, LocalModelUnavailable  # noqa: E402

app = FastAPI(title="ThreatLens local classifier")
_client = {}


class Batch(BaseModel):
    lines: List[str] = Field(..., min_length=1, max_length=20)


def client() -> LocalLLMClient:
    if "c" not in _client:
        try:
            _client["c"] = LocalLLMClient()
        except LocalModelUnavailable as e:
            raise HTTPException(503, f"model unavailable: {e}")
    return _client["c"]


@app.get("/health")
def health():
    return {"status": "ok", "model": client().model}


@app.post("/classify")
async def classify(b: Batch):
    c = client()
    t0 = time.perf_counter()
    try:
        findings = await c.classify_logs(b.lines)
    except ValueError as e:
        raise HTTPException(502, str(e))
    return {"findings": findings, "latency_s": round(time.perf_counter() - t0, 3), "model": c.model}
