"""FinetuneGuideTriage.txt PHASE 5 fallback — generate single-shot triage
outputs (table -> final JSON, no tool calls) from the singleshot-tuned
adapter and the stock base model over finetune/eval_triage_singleshot.jsonl.

Simpler than eval_triage_modal.py: single-shot records have no tool-call
turns, so this is a plain one-generation-per-row pass (same shape as the
report model's eval_modal.py), just against the triage prompt/table instead.

Usage:
    modal run finetune/eval_triage_singleshot_modal.py
    # writes finetune/eval_triage_singleshot_outputs.json locally
"""

import json
import pathlib

import modal

app = modal.App("mark2-triage-lora-singleshot-eval")

volume = modal.Volume.from_name("mark2-triage-lora-singleshot-out", create_if_missing=False)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        "torch==2.10.0",
        "torchvision==0.25.0",
        "torchao==0.17.0",
        "unsloth==2026.7.2",
        "unsloth_zoo==2026.7.2",
        "trl==0.24.0",
        "peft==0.19.1",
        "transformers==5.5.0",
        "datasets==4.3.0",
        "bitsandbytes==0.49.2",
        "accelerate==1.14.0",
        "xformers==0.0.35",
        "numpy==2.5.1",
    )
    .add_local_file(str(_REPO_ROOT / "finetune" / "eval_triage_singleshot.jsonl"), "/root/eval.jsonl", copy=True)
)

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
MAX_SEQ_LENGTH = 6144
ADAPTER_DIR = "/output/triage-3b-lora-singleshot"
MAX_NEW_TOKENS = 256  # final JSON only, no CVE dumps to reproduce


@app.cls(image=image, gpu="A10G", volumes={"/output": volume}, timeout=1800, scaledown_window=600)
class TriageSingleshotModel:
    variant: str = modal.parameter(default="tuned")

    @modal.enter()
    def load(self):
        from unsloth import FastLanguageModel

        model_name = ADAPTER_DIR if self.variant == "tuned" else BASE_MODEL
        self.model, self.tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=MAX_SEQ_LENGTH,
            dtype=None,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(self.model)

    @modal.method()
    def generate(self, messages):
        prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        out = self.model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            temperature=0.3,
            do_sample=True,
            pad_token_id=self.tokenizer.eos_token_id,
        )
        return self.tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        )


@app.local_entrypoint()
def main():
    eval_path = _REPO_ROOT / "finetune" / "eval_triage_singleshot.jsonl"
    rows = [json.loads(l) for l in eval_path.read_text().splitlines() if l.strip()]

    tuned = TriageSingleshotModel(variant="tuned")
    stock = TriageSingleshotModel(variant="stock")

    results = []
    for i, rec in enumerate(rows):
        system_msg, user_msg, gold_msg = rec["messages"][0], rec["messages"][1], rec["messages"][2]
        tuned_out = tuned.generate.remote([system_msg, user_msg])
        stock_out = stock.generate.remote([system_msg, user_msg])
        results.append({
            "index": i,
            "ordered_facts_json": user_msg["content"],
            "gold_final_text": gold_msg["content"],
            "tuned_final_text": tuned_out,
            "stock_final_text": stock_out,
        })
        print(f"[{i + 1}/{len(rows)}] done")

    out_path = _REPO_ROOT / "finetune" / "eval_triage_singleshot_outputs.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Wrote {len(results)} rows to {out_path}")
