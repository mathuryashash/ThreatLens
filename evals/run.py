"""ThreatLens eval runner.

  python evals/run.py --provider rules|gemini|groq|nim --split dev|test|all [--cache readonly]
                      [--env-file PATH] [--tag NAME] [--min-f1 X --min-precision Y]

Runs every golden line of the split through the real pipeline (see evals/pipeline.py),
then writes evals/results/<provider>_<split>[_<tag>].json and regenerates
evals/results/LEADERBOARD.md from all result files.

Metrics (line level; positive = attack):
  * detection precision / recall / F1 overall;
  * per golden category: support, detected (recall), category-correct (pred type acceptable);
  * per predicted type: precision;
  * confusion matrix golden category x predicted type ("-" = not flagged);
  * LLM calls, tokens in/out, cost estimate, p50/p95 per-call latency (uncached calls only;
    cached replays report the latency recorded when the call was first made).
"""
import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pipeline as P  # noqa: E402

GOLDEN = os.path.join(HERE, "golden", "golden.jsonl")
RESULTS = os.path.join(HERE, "results")
DEFAULT_ENV = os.path.join(P.BACKEND, ".env")

# Predicted types (pipeline vocabulary) that count as the *right category* for a golden label.
# SUSPICIOUS is accepted for categories the pipeline has no dedicated type for.
ACCEPT = {
    "SQLI": {"SQLI"}, "XSS": {"XSS"}, "PATH_TRAVERSAL": {"PATH_TRAVERSAL"}, "SSRF": {"SSRF"},
    "LOG4SHELL": {"LOG4SHELL", "MALWARE"}, "CMD_INJECTION": {"CMD_INJECTION", "MALWARE"},
    "BRUTE_FORCE": {"BRUTE_FORCE"}, "CRED_STUFFING": {"BRUTE_FORCE", "SUSPICIOUS"},
    "PASSWORD_SPRAY": {"BRUTE_FORCE", "SUSPICIOUS"}, "PRIV_ESC": {"PRIV_ESC"},
    "RECON": {"RECON", "PORT_SCAN"}, "DATA_EXFIL": {"DATA_EXFIL"},
    "B64_PAYLOAD": {"MALWARE", "CMD_INJECTION", "SUSPICIOUS", "SSRF"},
    "WEBSHELL": {"MALWARE", "CMD_INJECTION", "SUSPICIOUS"},
    "ANOMALOUS_LOGIN": {"SUSPICIOUS", "PRIV_ESC", "MALWARE", "BRUTE_FORCE"},
    "PERSISTENCE": {"MALWARE", "SUSPICIOUS", "PRIV_ESC"},
    "DEFENSE_EVASION": {"SUSPICIOUS", "MALWARE", "PRIV_ESC"},
    "PROMPT_INJECTION": {"SUSPICIOUS", "RECON", "MALWARE", "SQLI", "XSS"},
}
# USD per 1M tokens (input, output) - public list prices as of 2026-06; estimates only.
PRICES = {"gemini": (0.10, 0.40), "groq": (0.15, 0.60), "nim": (0.0, 0.0), "rules": (0.0, 0.0)}


def load_golden(split):
    rows = [json.loads(l) for l in open(GOLDEN, encoding="utf-8")]
    return rows if split == "all" else [r for r in rows if r["split"] == split]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 4), round(r, 4), round(f, 4)


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)


def score(rows, preds):
    by = {p["id"]: p for p in preds}
    tp = fp = fn = tn = 0
    cat = defaultdict(lambda: Counter())
    ptype = defaultdict(lambda: Counter())
    conf = defaultdict(Counter)
    errors = []
    for r in rows:
        p = by[r["id"]]
        attack = r["label"] == "attack"
        flagged = p["pred"] is not None
        gcat = r["category"] or "BENIGN"
        conf[gcat][p["pred"] or "-"] += 1
        if attack:
            cat[gcat]["n"] += 1
            if flagged:
                tp += 1
                cat[gcat]["detected"] += 1
                cat[gcat]["cat_ok"] += p["pred"] in ACCEPT.get(gcat, set())
            else:
                fn += 1
                errors.append(dict(kind="FN", id=r["id"], category=gcat, subtle=r["subtle"], line=r["line"],
                                   llm_failed=p["llm_failed"]))
        else:
            if flagged:
                fp += 1
                errors.append(dict(kind="FP", id=r["id"], pred=p["pred"], src=p["src"],
                                   hard_negative=r["hard_negative"], line=r["line"]))
            else:
                tn += 1
        if flagged:
            ptype[p["pred"]]["n"] += 1
            ptype[p["pred"]]["tp"] += attack
            ptype[p["pred"]]["src_" + p["src"]] += 1
    P_, R_, F_ = prf(tp, fp, fn)
    n_att = tp + fn
    cat_ok = sum(c["cat_ok"] for c in cat.values())
    return dict(
        overall=dict(precision=P_, recall=R_, f1=F_, tp=tp, fp=fp, fn=fn, tn=tn,
                     category_accuracy_on_attacks=round(cat_ok / n_att, 4) if n_att else None,
                     hard_negative_fp=sum(1 for e in errors if e["kind"] == "FP" and e["hard_negative"]),
                     hard_negatives=sum(1 for r in rows if r["hard_negative"])),
        per_category={k: dict(n=v["n"], detected=v["detected"], recall=round(v["detected"] / v["n"], 4),
                              category_correct=v["cat_ok"]) for k, v in sorted(cat.items())},
        per_predicted_type={k: dict(flagged=v["n"], precision=round(v["tp"] / v["n"], 4),
                                    by_rule=v["src_rule"], by_llm=v["src_llm"]) for k, v in sorted(ptype.items())},
        confusion={k: dict(v) for k, v in sorted(conf.items())},
        errors=errors,
    )


def write_leaderboard():
    rows = []
    for f in sorted(os.listdir(RESULTS)):
        if f.endswith(".json") and not f.startswith("judge"):
            d = json.load(open(os.path.join(RESULTS, f), encoding="utf-8"))
            if "overall" in d:
                rows.append(d)
    rows.sort(key=lambda d: (d["split"], -d["overall"]["f1"]))
    out = ["# ThreatLens eval leaderboard", "",
           "Auto-generated by `evals/run.py`. Line-level detection on the golden set "
           "(positive = attack). Latency = per LLM call; cost = list-price estimate.", "",
           "| run | split | lines | precision | recall | F1 | cat-acc | HN FP | LLM calls | tokens in/out | est. $ | p50 s | p95 s | failed lines |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for d in rows:
        o, c = d["overall"], d["cost"]
        out.append(f"| {d['run']} | {d['split']} | {d['n_lines']} | {o['precision']:.3f} | {o['recall']:.3f} | {o['f1']:.3f} | "
                   f"{o['category_accuracy_on_attacks']:.3f} | {o['hard_negative_fp']}/{o['hard_negatives']} | {c['llm_calls']} | "
                   f"{c['tokens_in']}/{c['tokens_out']} | {c['usd_estimate']:.4f} | {c['latency_p50_s']} | {c['latency_p95_s']} | {d['llm_failed_lines']} |")
    open(os.path.join(RESULTS, "LEADERBOARD.md"), "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, choices=["rules", "gemini", "groq", "nim"])
    ap.add_argument("--split", default="dev", choices=["dev", "test", "all"])
    ap.add_argument("--cache", default="readwrite", choices=["readwrite", "readonly"])
    ap.add_argument("--env-file", default=DEFAULT_ENV)
    ap.add_argument("--tag", default="")
    ap.add_argument("--min-f1", type=float, default=None)
    ap.add_argument("--min-precision", type=float, default=None)
    ap.add_argument("--min-recall", type=float, default=None)
    a = ap.parse_args(argv)

    if a.provider != "rules" and a.cache != "readonly":
        P.load_keys(a.env_file)
    elif a.provider != "rules":
        # readonly replay: dummy keys so clients construct; every call must hit the cache
        P.settings.GEMINI_API_KEY = P.settings.GEMINI_API_KEY or "replay"
        P.settings.GROQ_API_KEY = P.settings.GROQ_API_KEY or "replay"
        os.environ.setdefault("NVIDIA_API_KEY", "replay")
    log = P.CallLog()
    P.install_cache(log, a.cache)
    rec = P.Recording(P.make_client(a.provider))

    rows = load_golden(a.split)
    streams = defaultdict(list)
    for r in rows:
        streams[r["stream"]].append(r)
    preds, walls, statuses = [], {}, {}
    t0 = time.perf_counter()

    async def run_all():  # one event loop: the app's shared httpx clients are loop-bound
        for s, srows in streams.items():
            srows.sort(key=lambda r: r["idx"])
            out, wall, st = await P.run_stream(srows, srows[0]["source_type"], rec)
            preds.extend(out)
            walls[s], statuses[s] = round(wall, 2), st

    asyncio.run(run_all())
    res = score(rows, preds)
    tin, tout = log.tokens()
    lat = [c["latency_s"] for c in log.calls if c["status"] == 200]
    pin, pout = PRICES[a.provider]
    run = a.provider + (f"+{a.tag}" if a.tag else "")
    res.update(
        run=run, provider=a.provider, model=rec.model, split=a.split, n_lines=len(rows),
        n_attacks=sum(r["label"] == "attack" for r in rows),
        llm_failed_lines=sum(p["llm_failed"] for p in preds),
        stream_wall_s=walls, job_status=statuses,
        cost=dict(llm_calls=len(log.calls), cached_calls=sum(c["cached"] for c in log.calls),
                  tokens_in=tin, tokens_out=tout,
                  usd_estimate=round(tin / 1e6 * pin + tout / 1e6 * pout, 6),
                  latency_p50_s=pct(lat, 0.5), latency_p95_s=pct(lat, 0.95)),
        total_wall_s=round(time.perf_counter() - t0, 2),
        predictions=preds,
    )
    os.makedirs(RESULTS, exist_ok=True)
    name = f"{a.provider}_{a.split}{('_' + a.tag) if a.tag else ''}.json"
    json.dump(res, open(os.path.join(RESULTS, name), "w", encoding="utf-8"), indent=1)
    write_leaderboard()
    o = res["overall"]
    print(f"{run} {a.split}: n={len(rows)} P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f} "
          f"cat_acc={o['category_accuracy_on_attacks']} tp={o['tp']} fp={o['fp']} fn={o['fn']} "
          f"calls={res['cost']['llm_calls']} (cached {res['cost']['cached_calls']}) tok={tin}/{tout} "
          f"p50={res['cost']['latency_p50_s']} p95={res['cost']['latency_p95_s']} failed={res['llm_failed_lines']} -> results/{name}")
    ok = True
    for name_, thr, val in (("f1", a.min_f1, o["f1"]), ("precision", a.min_precision, o["precision"]),
                            ("recall", a.min_recall, o["recall"])):
        if thr is not None and val < thr:
            print(f"THRESHOLD FAIL: {name_} {val:.4f} < {thr}")
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
