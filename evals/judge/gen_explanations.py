"""Generate explanations to be judged (evals/judge/explanations.json).

Incidents = golden attack lines grouped by (stream, category), up to 5 lines each.
For each incident we collect explanations from:
  * gemini  - the real GeminiClient.explain_threat (cached via evals/pipeline disk cache)
  * mock    - MockLLMClient.explain_threat (the offline fallback; canned per threat type)
Part: dev-split incidents -> judge "dev" (prompt iteration), test-split -> "heldout".
"""
import asyncio
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pipeline as P  # noqa: E402
from app.llm import MockLLMClient, GeminiClient  # noqa: E402
from app.redactor import redact_content  # noqa: E402

# golden category -> threat_type the pipeline would carry (what the explainer sees)
TYPE = {"CRED_STUFFING": "BRUTE_FORCE", "PASSWORD_SPRAY": "BRUTE_FORCE", "B64_PAYLOAD": "SUSPICIOUS",
        "WEBSHELL": "MALWARE", "ANOMALOUS_LOGIN": "SUSPICIOUS", "PERSISTENCE": "SUSPICIOUS",
        "DEFENSE_EVASION": "SUSPICIOUS", "PROMPT_INJECTION": "SUSPICIOUS", "LOG4SHELL": "LOG4SHELL",
        "CMD_INJECTION": "CMD_INJECTION"}


def incidents():
    rows = [json.loads(l) for l in open(os.path.join(os.path.dirname(HERE), "golden", "golden.jsonl"), encoding="utf-8")]
    g = defaultdict(list)
    for r in rows:
        if r["label"] == "attack":
            g[(r["split"], r["stream"], r["category"])].append(r)
    out = []
    for (split, stream, cat), rs in sorted(g.items()):
        rs = rs[:5]
        ip = P.main_mod.parse_log_line(rs[0]["line"], rs[0]["source_type"]).get("source_ip")
        out.append(dict(incident=f"{stream}:{cat}", part="dev" if split == "dev" else "heldout", category=cat,
                        threat=dict(threat_type=TYPE.get(cat, cat), severity="HIGH", severity_score=75,
                                    source_ip=ip, summary=f"Activity consistent with {cat.replace('_', ' ').lower()}",
                                    attack_pattern=None),
                        logs=[redact_content(r["line"]) for r in rs]))
    return out


async def main():
    P.load_keys(sys.argv[1] if len(sys.argv) > 1 else os.path.join(P.BACKEND, ".env"))
    P.install_cache(P.CallLog())
    gem, mock = GeminiClient(), MockLLMClient()
    out = []
    for inc in incidents():
        for name, cl in (("gemini", gem), ("mock", mock)):
            try:
                e = await cl.explain_threat(inc["threat"], inc["logs"])
            except Exception as ex:
                print("explain failed", inc["incident"], name, type(ex).__name__)
                continue
            out.append(dict(id=f"{inc['incident']}:{name}", source=name, **inc, output=e))
    json.dump(out, open(os.path.join(HERE, "explanations.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("explanations", len(out), "incidents", len(out) // 2)


if __name__ == "__main__":
    asyncio.run(main())
