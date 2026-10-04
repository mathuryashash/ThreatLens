"""Env-gated Langfuse tracing for LLM calls.

Tracing is OFF unless both LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set
(LANGFUSE_HOST is optional). When off, ``llm_span`` yields a no-op span and the
``langfuse`` package is never imported, so the app has no hard dependency on it.

Tests can inject any object exposing ``start_as_current_observation(**kw)`` (a
context manager yielding something with ``.update(**kw)``) via ``set_client``.
"""
import os
from contextlib import contextmanager
from typing import Any, Optional

_client: Any = None
_client_resolved = False


class _NoopSpan:
    def update(self, **kwargs) -> None:
        return None


NOOP_SPAN = _NoopSpan()


def is_enabled() -> bool:
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"))


def set_client(client: Any) -> None:
    """Override the tracing client (tests / custom exporters). ``None`` resets."""
    global _client, _client_resolved
    _client = client
    _client_resolved = client is not None


def _get_client() -> Optional[Any]:
    global _client, _client_resolved
    if _client_resolved:
        return _client
    _client_resolved = True
    if not is_enabled():
        _client = None
        return None
    try:
        from langfuse import Langfuse  # imported lazily: optional dependency
        _client = Langfuse()
    except Exception as e:  # never let tracing break classification
        print(f"Langfuse disabled: {type(e).__name__}")
        _client = None
    return _client


@contextmanager
def llm_span(name: str, *, model: Optional[str] = None, input: Any = None, metadata: Optional[dict] = None):
    """Wrap one LLM call in a Langfuse *generation* observation (or a no-op)."""
    client = _get_client()
    if client is None:
        yield NOOP_SPAN
        return
    try:
        cm = client.start_as_current_observation(name=name, as_type="generation", model=model,
                                                 input=input, metadata=metadata or {})
        span = cm.__enter__()
    except Exception as e:
        print(f"Langfuse span start failed: {type(e).__name__}")
        yield NOOP_SPAN
        return
    exc_info = (None, None, None)
    try:
        yield span
    except BaseException as e:
        exc_info = (type(e), e, e.__traceback__)
        try:
            span.update(level="ERROR", status_message=type(e).__name__)
        except Exception:
            pass
        raise
    finally:
        try:
            cm.__exit__(*exc_info)
        except Exception:
            pass


def usage_from_openai(data: dict) -> dict:
    u = (data or {}).get("usage") or {}
    return {"input": u.get("prompt_tokens"), "output": u.get("completion_tokens")}


def usage_from_gemini(data: dict) -> dict:
    u = (data or {}).get("usageMetadata") or {}
    return {"input": u.get("promptTokenCount"),
            "output": (u.get("candidatesTokenCount") or 0) + (u.get("thoughtsTokenCount") or 0)}
