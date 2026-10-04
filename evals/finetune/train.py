"""QLoRA fine-tune of a small instruct model on the generated ThreatLens windows.

  python evals/finetune/train.py --run r16 [--model Qwen/Qwen2.5-1.5B-Instruct] [--r 16] [--lr 2e-4]
                                 [--epochs 1] [--max-len 2048] [--limit N]

* 4-bit NF4 base (bitsandbytes) + LoRA on all attention/MLP projections (peft), trl SFTTrainer,
  loss on the assistant JSON only (completion-only).
* Tracking: CSV per run (evals/finetune/runs/<run>/log.csv: step, loss, eval_loss, lr) + summary.json
  with train time and peak VRAM (torch.cuda.max_memory_allocated / reserved). Loss curve PNG if
  matplotlib is available.
* Adapter saved to evals/finetune/runs/<run>/adapter (gitignored: weights).
"""
import argparse
import csv
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--model", default="unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit")
    ap.add_argument("--r", type=int, default=16)
    ap.add_argument("--alpha", type=int, default=None)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--max-len", type=int, default=2048)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainerCallback
    from trl import SFTConfig, SFTTrainer

    out = os.path.join(HERE, "runs", a.run)
    os.makedirs(out, exist_ok=True)
    ds = load_dataset("json", data_files={"train": os.path.join(DATA, "train.jsonl"),
                                          "val": os.path.join(DATA, "val.jsonl")})
    # conversational prompt/completion -> TRL masks the prompt, loss on the assistant JSON only
    ds = ds.map(lambda ex: {"prompt": ex["messages"][:-1], "completion": ex["messages"][-1:]},
                remove_columns=["messages", "meta"])
    if a.limit:
        ds["train"] = ds["train"].select(range(min(a.limit, len(ds["train"]))))

    tok = AutoTokenizer.from_pretrained(a.model)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.bfloat16)
    from transformers import AutoConfig
    prequant = getattr(AutoConfig.from_pretrained(a.model), "quantization_config", None) is not None
    model = AutoModelForCausalLM.from_pretrained(a.model, **({} if prequant else {"quantization_config": bnb}),
                                                 dtype=torch.bfloat16,
                                                 device_map={"": 0}, attn_implementation="sdpa")
    lora = LoraConfig(r=a.r, lora_alpha=a.alpha or 2 * a.r, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    cfg = SFTConfig(
        output_dir=os.path.join(out, "ckpt"), num_train_epochs=a.epochs, per_device_train_batch_size=a.batch,
        per_device_eval_batch_size=1, gradient_accumulation_steps=a.grad_accum, learning_rate=a.lr,
        lr_scheduler_type="cosine", warmup_ratio=0.05, logging_steps=5, eval_strategy="steps", eval_steps=20,
        save_strategy="no", bf16=True, gradient_checkpointing=True, max_length=a.max_len,
        completion_only_loss=True, report_to=[], seed=42, optim="paged_adamw_8bit",
    )
    rows = []

    class CSVLog(TrainerCallback):
        def on_log(self, args, state, control, logs=None, **kw):
            if logs:
                rows.append(dict(step=state.global_step, loss=logs.get("loss"), eval_loss=logs.get("eval_loss"),
                                 lr=logs.get("learning_rate"), t=round(time.perf_counter() - t0, 1)))

    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds["train"], eval_dataset=ds["val"],
                         processing_class=tok, peft_config=lora, callbacks=[CSVLog()])
    torch.cuda.reset_peak_memory_stats()
    t0 = time.perf_counter()
    trainer.train()
    train_s = time.perf_counter() - t0
    ev = trainer.evaluate()
    trainer.model.save_pretrained(os.path.join(out, "adapter"))
    tok.save_pretrained(os.path.join(out, "adapter"))
    with open(os.path.join(out, "log.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["step", "loss", "eval_loss", "lr", "t"])
        w.writeheader()
        w.writerows(rows)
    summary = dict(run=a.run, model=a.model, lora_r=a.r, lora_alpha=a.alpha or 2 * a.r, lr=a.lr, epochs=a.epochs,
                   effective_batch=a.batch * a.grad_accum, max_len=a.max_len, train_examples=len(ds["train"]),
                   val_examples=len(ds["val"]), steps=trainer.state.global_step, train_seconds=round(train_s, 1),
                   final_eval_loss=round(ev["eval_loss"], 4),
                   first_train_loss=next((r["loss"] for r in rows if r["loss"] is not None), None),
                   last_train_loss=next((r["loss"] for r in reversed(rows) if r["loss"] is not None), None),
                   peak_vram_allocated_gb=round(torch.cuda.max_memory_allocated() / 2**30, 2),
                   peak_vram_reserved_gb=round(torch.cuda.max_memory_reserved() / 2**30, 2),
                   gpu=torch.cuda.get_device_name(0), torch=torch.__version__)
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=1)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        tr = [(r["step"], r["loss"]) for r in rows if r["loss"] is not None]
        va = [(r["step"], r["eval_loss"]) for r in rows if r["eval_loss"] is not None]
        plt.figure(figsize=(6, 3.5))
        if tr:
            plt.plot(*zip(*tr), label="train")
        if va:
            plt.plot(*zip(*va), "o-", label="val")
        plt.xlabel("step"), plt.ylabel("loss"), plt.title(a.run), plt.legend(), plt.tight_layout()
        plt.savefig(os.path.join(out, "loss.png"), dpi=110)
    except Exception as e:  # plotting is optional
        print("no plot:", type(e).__name__)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
