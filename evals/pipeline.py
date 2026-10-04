"""Run golden-set lines through the REAL ThreatLens pipeline, in-process.

Uses ``app.main.process_log_ingest_job`` unchanged (parser -> redactor -> rules.process_rules
-> unmatched lines to the LLM in batches of 20) against the in-memory mock DB. Only two seams
are swapped:

* ``app.main.get_llm_client`` returns the provider client chosen for the eval, wrapped so we
  can record every finding (pre-dedup) per line;
* ``app.llm._post_with_retry`` is wrapped by a disk cache keyed by sha256(url + payload), so
  re-runs are free/deterministic and CI can replay LLM calls with no keys.

Line-level prediction for a golden line:
  rule:  check_pattern_rules(line) matched (category = rule type), or the line's event was linked
         to a rule BRUTE_FORCE correlation threat;
  llm:   the line's index was in related_event_indices of any finding the LLM returned for its
         batch (category = finding threat_type). Rule takes precedence (rule-matched lines never
         reach the LLM anyway).
"""
import hashlib
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
CACHE_DIR = os.path.join(ROOT, "evals", "cache")

# never touch a real DB from an eval
os.environ.update(SUPABASE_URL="", SUPABASE_SERVICE_ROLE_KEY="", DATABASE_URL="", ALLOW_MOCK_DB="true")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import httpx  # noqa: E402

from app import llm as llm_mod  # noqa: E402
from app import main as main_mod  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import db  # noqa: E402
from app.rules import check_pattern_rules  # noqa: E402

KEY_NAMES = ("GEMINI_API_KEY", "GROQ_API_KEY", "NVIDIA_API_KEY")


def load_keys(env_file):
    """Load only LLM key vars from a dotenv file into os.environ/settings. Values never printed."""
    if env_file and os.path.exists(env_file):
        for raw in open(env_file, encoding="utf-8"):
            line = raw.strip()
            if "=" not in line or line.startswith("#"):
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k in KEY_NAMES and v and not os.environ.get(k):
                os.environ[k] = v
    settings.GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY
    settings.GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or settings.GROQ_API_KEY


# ---------------------------------------------------------------- disk cache
class CallLog:
    def __init__(self):
        self.calls = []  # dicts: cached, latency_s, in_tok, out_tok, status

    def tokens(self):
        return sum(c["in_tok"] or 0 for c in self.calls), sum(c["out_tok"] or 0 for c in self.calls)


def _usage(data):
    if not isinstance(data, dict):
        return None, None
    if "usage" in data:
        u = data["usage"] or {}
        return u.get("prompt_tokens"), u.get("completion_tokens")
    u = data.get("usageMetadata") or {}
    out = (u.get("candidatesTokenCount") or 0) + (u.get("thoughtsTokenCount") or 0)
    return u.get("promptTokenCount"), out if u else None


def install_cache(call_log, mode="readwrite"):
    """mode: readwrite (default) | readonly (CI: miss = error, no network)."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    real = llm_mod._orig_post_with_retry if hasattr(llm_mod, "_orig_post_with_retry") else llm_mod._post_with_retry
    llm_mod._orig_post_with_retry = real

    async def cached_post(client, url, **kwargs):
        full_url = str(client.base_url).rstrip("/") + url if url.startswith("/") else url
        body = json.dumps({"url": full_url, "json": kwargs.get("json")}, sort_keys=True)
        key = hashlib.sha256(body.encode()).hexdigest()
        path = os.path.join(CACHE_DIR, key[:2], key + ".json")
        req = httpx.Request("POST", full_url)
        if os.path.exists(path):
            ent = json.load(open(path, encoding="utf-8"))
            i, o = _usage(ent["data"])
            call_log.calls.append(dict(cached=True, latency_s=ent["latency_s"], in_tok=i, out_tok=o, status=ent["status"]))
            return httpx.Response(ent["status"], json=ent["data"], request=req)
        if mode == "readonly":
            raise RuntimeError(f"cache miss in readonly mode ({key[:12]})")
        t0 = time.perf_counter()
        resp = await real(client, url, **kwargs)
        dt = time.perf_counter() - t0
        try:
            data = resp.json()
        except Exception:
            data = {"_text": resp.text[:500]}
        i, o = _usage(data)
        call_log.calls.append(dict(cached=False, latency_s=dt, in_tok=i, out_tok=o, status=resp.status_code))
        if resp.is_success:  # never cache errors
            os.makedirs(os.path.dirname(path), exist_ok=True)
            json.dump({"status": resp.status_code, "latency_s": dt, "data": data, "url_host": httpx.URL(full_url).host},
                      open(path, "w", encoding="utf-8"))
        return httpx.Response(resp.status_code, json=data, request=req)

    llm_mod._post_with_retry = cached_post


# ---------------------------------------------------------------- providers
class NoLLM(llm_mod.LLMClient):
    model = "none"

    async def classify_logs(self, log_batch):
        return []

    async def explain_threat(self, threat_data, related_logs):
        raise NotImplementedError


class NimClient(llm_mod.GroqClient):
    """NVIDIA NIM (OpenAI-compatible); reuses the Groq prompt verbatim."""

    def __init__(self):
        key = os.environ.get("NVIDIA_API_KEY")
        if not key:
            raise RuntimeError("NVIDIA_API_KEY not set")
        self.api_key = key
        self.client = httpx.AsyncClient(base_url="https://integrate.api.nvidia.com/v1",
                                        headers={"Authorization": f"Bearer {key}"}, timeout=60.0)
        self.model = os.environ.get("NIM_MODEL", "meta/llama-3.3-70b-instruct")
        self.explain_model = self.model


class Recording(llm_mod.LLMClient):
    """Wraps a client; records findings per batch (keyed by the batch's line tuple)."""

    def __init__(self, inner):
        self.inner = inner
        self.model = getattr(inner, "model", "?")
        self.batches = []  # (lines, findings | None on failure)

    async def classify_logs(self, log_batch):
        try:
            f = await self.inner.classify_logs(log_batch)
        except Exception as e:
            self.batches.append((list(log_batch), None, type(e).__name__))
            raise
        self.batches.append((list(log_batch), f, None))
        return f

    async def explain_threat(self, threat_data, related_logs):
        return await self.inner.explain_threat(threat_data, related_logs)


def make_client(provider):
    if provider == "rules":
        return NoLLM()
    if provider == "gemini":
        if not settings.GEMINI_API_KEY:
            raise RuntimeError("GEMINI_API_KEY not set")
        return llm_mod.GeminiClient()
    if provider == "groq":
        if not settings.GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY not set")
        return llm_mod.GroqClient()
    if provider == "nim":
        return NimClient()
    if provider == "local":
        from app.local_llm import LocalLLMClient  # lazy: needs torch/transformers + model weights
        return LocalLLMClient()
    raise ValueError(provider)


# ---------------------------------------------------------------- run
async def run_stream(rows, source_type, rec):
    """Ingest one stream through process_log_ingest_job; return per-row predictions."""
    sid = db.create_session()["id"]
    lines = [r["line"] for r in rows]
    job = db.create_job(sid, len(lines))
    n_before = len(rec.batches)
    main_mod.get_llm_client = lambda: rec
    t0 = time.perf_counter()
    await main_mod.process_log_ingest_job(job["id"], sid, source_type, lines)
    wall = time.perf_counter() - t0
    # map events -> golden row (events are created in order, one per line)
    events = [e for e in db.parsed_events.values() if e["session_id"] == sid]
    raw_order = {rid: i for i, rid in enumerate(k for k, v in db.raw_logs.items() if v["session_id"] == sid)}
    ev_row = {e["id"]: raw_order[e["raw_log_id"]] for e in events}
    bf_rows = set()
    for te in db.threat_events:
        t = db.threats.get(te["threat_id"])
        if t and t["session_id"] == sid and t["classification_source"] == "rule" and t["threat_type"] == "BRUTE_FORCE":
            bf_rows.add(ev_row.get(te["event_id"]))
    redacted = [db.raw_logs[rid]["redacted_content"] for rid in sorted(raw_order, key=raw_order.get)]
    llm_pred, failed, used = {}, set(), set()
    for blines, findings, err in rec.batches[n_before:]:
        # batch lines are redacted contents of unmatched rows; batches may complete out of order
        idx_map = []
        for bl in blines:
            j = next(i for i, rl in enumerate(redacted) if rl == bl and i not in used)
            used.add(j)
            idx_map.append(j)
        if findings is None:
            failed.update(idx_map)
            continue
        for f in findings:
            for k in f["related_event_indices"]:
                llm_pred.setdefault(idx_map[k], f["threat_type"])
    out = []
    for i, r in enumerate(rows):
        m = check_pattern_rules(r["line"])
        if m:
            pred, src = m[0], "rule"
        elif i in bf_rows:
            pred, src = "BRUTE_FORCE", "rule"
        elif i in llm_pred:
            pred, src = llm_pred[i], "llm"
        else:
            pred, src = None, None
        out.append(dict(id=r["id"], pred=pred, src=src, llm_failed=i in failed))
    status = db.get_job(job["id"])["status"]
    return out, wall, status
