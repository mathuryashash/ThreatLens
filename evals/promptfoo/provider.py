"""Promptfoo python provider: runs golden streams through the REAL ThreatLens pipeline.

promptfoo calls call_api(prompt, options, context). The prompt is the golden stream name;
config.provider = gemini|groq|rules, config.cache = readwrite|readonly (CI uses readonly: every
LLM call must replay from evals/cache, no keys / network needed).
Output JSON: {"stream", "flagged": {id: type}, "attack_ids": [...], "benign_ids": [...]}
"""
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVALS = os.path.dirname(HERE)
sys.path.insert(0, EVALS)

_state = {}


def _setup(provider, cache):
    if _state:
        return _state
    import pipeline as P
    if cache == "readwrite":
        P.load_keys(os.environ.get("THREATLENS_ENV_FILE", os.path.join(P.BACKEND, ".env")))
    else:
        P.settings.GEMINI_API_KEY = P.settings.GEMINI_API_KEY or "replay"
        P.settings.GROQ_API_KEY = P.settings.GROQ_API_KEY or "replay"
    P.install_cache(P.CallLog(), cache)
    _state.update(P=P)
    return _state


def call_api(prompt, options, context):
    cfg = (options or {}).get("config", {}) or {}
    st = _setup(cfg.get("provider", "gemini"), cfg.get("cache", "readonly"))
    P = st["P"]
    stream = prompt.strip()
    rows = [json.loads(l) for l in open(os.path.join(EVALS, "golden", "golden.jsonl"), encoding="utf-8")]
    rows = sorted([r for r in rows if r["stream"] == stream], key=lambda r: r["idx"])
    if not rows:
        return {"error": f"unknown stream {stream}"}
    # each promptfoo call gets a fresh event loop; the app's shared httpx clients are loop-bound
    P.llm_mod.GeminiClient._shared_client = None
    P.llm_mod.GroqClient._shared_client = None
    rec = P.Recording(P.make_client(cfg.get("provider", "gemini")))
    try:
        preds, _, status = asyncio.run(P.run_stream(rows, rows[0]["source_type"], rec))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    out = {"stream": stream, "job_status": status,
           "flagged": {p["id"]: p["pred"] for p in preds if p["pred"]},
           "llm_failed": [p["id"] for p in preds if p["llm_failed"]],
           "attack_ids": [r["id"] for r in rows if r["label"] == "attack"],
           "benign_ids": [r["id"] for r in rows if r["label"] == "benign"]}
    return {"output": json.dumps(out)}
