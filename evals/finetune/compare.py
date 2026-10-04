"""Head-to-head table on the TEST split from saved result JSONs (no API calls).

  python evals/finetune/compare.py  -> evals/finetune/HEAD_TO_HEAD.md
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(os.path.dirname(HERE), "results")
RUNS = [("rules only", "rules_test.json"),
        ("rules + Qwen2.5-0.5B base (local, no LoRA)", "local_test_base.json"),
        ("rules + Qwen2.5-0.5B QLoRA (local)", "local_test_ft.json"),
        ("rules + Groq gpt-oss-20b (API)", "groq_test.json"),
        ("rules + Gemini flash-lite (API)", "gemini_test.json")]


def main():
    rows, cats = [], {}
    for name, f in RUNS:
        p = os.path.join(RES, f)
        if not os.path.exists(p):
            continue
        d = json.load(open(p, encoding="utf-8"))
        o, c, loc = d["overall"], d["cost"], d.get("local") or {}
        jv = loc.get("json_validity_rate")
        if jv is None and c["llm_calls"]:
            jv = "no failed batch*" if d["llm_failed_lines"] == 0 else f"{d['llm_failed_lines']} failed lines*"
        elif jv is not None:
            jv = f"{jv:.3f} ({loc['json_valid_first_try']}/{loc['batches']})"
        rows.append(f"| {name} | `{d['model']}` | {o['precision']:.3f} | {o['recall']:.3f} | **{o['f1']:.3f}** | "
                    f"{o['category_accuracy_on_attacks']:.3f} | {o['fp']} | {o['fn']} | {o['hard_negative_fp']}/{o['hard_negatives']} | "
                    f"{jv if jv is not None else 'n/a'} | {c['llm_calls']} | {c['latency_p50_s']} | {c['latency_p95_s']} | "
                    f"${c['usd_estimate']:.4f} | {d['llm_failed_lines']} | `{f}` |")
        cats[name] = d["per_category"]
    out = ["# Head-to-head on the held-out TEST split (203 lines, 108 attacks)", "",
           "Same runner (`evals/run.py`), same pipeline (parser -> redactor -> rules -> unmatched lines to the LLM in "
           "batches of 20). API rows are the cached results from branch `hermes/threatlens-evals` (not re-run). "
           "Latency = per 20-line LLM batch (local: RTX 4060 Laptop, transformers generate, greedy). Cost = API list "
           "price estimate; local = $0 API spend (electricity not counted).", "",
           "| run | model | P | R | F1 | cat-acc | FP | FN | hard-neg FP | JSON valid | LLM batches | p50 s | p95 s | est. $ | failed lines | file |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"] + rows
    out += ["", "\\* API providers run in JSON mode (`response_format=json_object` / Gemini JSON); a batch counts as invalid only "
            "if it failed, and 0 lines failed in those runs.", "", "## Per-category recall (detected / n)", ""]
    names = list(cats)
    allc = sorted({k for v in cats.values() for k in v})
    out.append("| category | " + " | ".join(names) + " |")
    out.append("|---|" + "---|" * len(names))
    for k in allc:
        out.append(f"| {k} | " + " | ".join(f"{cats[n][k]['detected']}/{cats[n][k]['n']}" if k in cats[n] else "-" for n in names) + " |")
    open(os.path.join(HERE, "HEAD_TO_HEAD.md"), "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print("\n".join(out))


if __name__ == "__main__":
    main()
