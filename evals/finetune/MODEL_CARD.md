# Model card: ThreatLens log classifier (Qwen2.5-0.5B QLoRA adapter, v2)

**Bottom line:** the fine-tuned 0.5B model does **not** beat the API LLMs. On the held-out TEST split its F1 is 0.748.
Gemini flash-lite scores 0.991 and Groq gpt-oss-20b scores 0.963. It is only 0.008 F1 above rules-only (0.740).
It costs $0 per call and runs on-device and offline, so log lines never leave the machine.

## What it is
- Base: `unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit` (4-bit NF4, double quant, bf16 compute).
- Adapter: LoRA r=16, alpha=32, on q/k/v/o/gate/up/down projections. 1 epoch, lr 2e-4 (cosine, 5% warmup),
  effective batch 8, max length 2600 tokens. Windows longer than that are **dropped, never truncated**,
  so the target JSON is never cut off.
- Task: the ThreatLens `classify` step. Input is a window of up to 20 redacted log lines that the regex rules
  did not match. Output is JSON findings `{line index, threat type, severity, explanation}` (same prompt and schema as the API providers).
- Serving: `--provider local` in `evals/run.py` / `backend/app/local_llm.py` (`LOCAL_ADAPTER_PATH`), plus
  `evals/finetune/serve_local.py` (OpenAI-style HTTP endpoint).
- Weights are gitignored (`evals/finetune/runs/*/adapter/`, about 35 MB safetensors). To rebuild them, run the commands in VERIFY.md.

## Training data (`evals/finetune/gen_data.py`, seed 7)
- Synthetic nginx/auth streams plus streams seeded from **DEV-split** lines only. No TEST line is used.
- v2: 609 train / 55 val windows (305 with no finding; `--benign-frac 0.4`), 10,339 lines (1,695 attack / 8,644 benign),
  1,656 hard negatives. After the over-length filter, 478 train / 42 val windows were used.
- v1 (`data_v1/stats.json`): 472/42 windows, no all-benign windows. v2 adds all-benign windows because DEV error
  analysis showed that v1 reported findings in benign-only windows. That fix was chosen on DEV, not on TEST.
- Leakage control (`data/overlap_report.json`): every generated line is compared with all 203 TEST lines using
  normalised token Jaccard (IPs, timestamps, pids and ports masked). Lines at Jaccard >= 0.8 are dropped (853 dropped).
  Result: **0 exact overlaps and 0 lines over the threshold**; max kept Jaccard is 0.8.

## Training run (RTX 4060 Laptop 8 GB, `runs/v2_r16_lr2e-4/summary.json`)
60 steps, 752.8 s. Train loss went from 0.8823 to 0.1287. Final val loss was 0.11. Peak VRAM allocated was 5.15 GB
(14.35 GB reserved incl. shared memory). Mid-run eval was turned off because it spilled into shared memory and slowed steps by about 10x.

## Evaluation (same runner and pipeline as the API rows; single greedy run)
| split | run | P | R | F1 | JSON valid (first try) | p50 / p95 s per 20-line batch |
|---|---|---|---|---|---|---|
| TEST | rules only | 0.985 | 0.593 | 0.740 | n/a | n/a |
| TEST | base 0.5B, no LoRA | 0.985 | 0.593 | 0.740 | 9/9 | 11.4 / 15.0 |
| TEST | QLoRA v1 | 0.674 | 0.861 | 0.756 | 8/9 | 13.8 / 104.1 |
| TEST | **QLoRA v2** | 0.822 | 0.685 | **0.748** | 9/9 | 26.7 / 61.2 |
| TEST | Groq gpt-oss-20b | 0.955 | 0.972 | 0.963 | API JSON mode | 1.13 / 27.1 |
| TEST | Gemini flash-lite | 0.991 | 0.991 | 0.991 | API JSON mode | 1.77 / 2.33 |
| DEV | base / v1 / v2 | 1.000 / 0.564 / 0.692 | 0.500 / 0.688 / 0.703 | 0.667 / 0.620 / 0.698 | 8/8, 6/8, 8/8 | v2: 15.6 / 54.0 |

On both splits the base model added **zero** findings beyond the rules. Fine-tuning taught it to report
findings at all: on TEST, v2 had 25 LLM-sourced predictions and lifted CRED_STUFFING recall from 0/12 to 7/12. It still misses
password spray, B64 payloads, data exfil, webshells and most RECON. It also raises 6/31 hard-negative false positives (rules-only raises 1/31).
v1 has higher recall but 45 false positives. On TEST, v1 F1 is 0.756 vs 0.748 for v2, which is within noise. v2 was picked on DEV (0.698 vs 0.620) before it was run on TEST.

## Where it wins / limitations
- Wins: $0 API spend per call, fully offline and on-device (private logs never leave the host), 100% valid JSON
  on 17/17 batches (dev+test), and it fits an 8 GB laptop GPU.
- Loses: F1 is 0.24 below Gemini. Latency is about 15x slower at p50 than the APIs on this laptop (HF `generate`, no vLLM/llama.cpp).
- Synthetic, single-annotator golden set (203 test lines). Each number comes from one run, with no confidence intervals.
- Rules + LLM pipeline: the LLM only sees lines the rules did not match, so the F1 numbers measure the whole system, not the model alone.
- Not for production alerting.
