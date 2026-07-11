"""Step 13 (FinetuneGuide.txt PHASE 5) — run the tuned report-LoRA adapter over
the held-out eval.jsonl inputs and dump raw generations to a local JSON file.

Generation happens on Modal (same GPU stack as training); the actual pass/fail
validation against the REAL validators (_validate_report_text, _parse_report,
_validate_report_severities from agent.py) happens locally in
finetune/score_eval.py, since agent.py imports cleanly with no GPU/network
dependency and the guide requires reusing those exact functions, not a
reimplementation.

Usage:
    modal run finetune/eval_modal.py
    # writes finetune/eval_outputs.json locally
"""

import json
import pathlib

import modal

app = modal.App("mark2-report-lora-eval")

volume = modal.Volume.from_name("mark2-report-lora-out", create_if_missing=False)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        # Same pinned stack as train_modal.py — see modal_training_issues.md #2.
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
    .add_local_file(str(_REPO_ROOT / "eval.jsonl"), "/root/eval.jsonl", copy=True)
)

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
MAX_SEQ_LENGTH = 4096
ADAPTER_DIR = "/output/report-3b-lora"


@app.function(image=image, gpu="A10G", volumes={"/output": volume}, timeout=1800)
def generate():
    # Unsloth must be imported before trl/transformers/peft (modal_training_issues.md #4).
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=ADAPTER_DIR,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )
    FastLanguageModel.for_inference(model)

    rows = []
    with open("/root/eval.jsonl") as f:
        for line in f:
            rows.append(json.loads(line))

    results = []
    for i, rec in enumerate(rows):
        messages = rec["messages"]
        system_msg, user_msg, gold_msg = messages[0], messages[1], messages[2]
        prompt = tokenizer.apply_chat_template(
            [system_msg, user_msg],
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        out = model.generate(
            **inputs,
            max_new_tokens=2000,
            temperature=0.3,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id,
        )
        raw_output = tokenizer.decode(
            out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
        )
        results.append({
            "index": i,
            "ordered_facts_json": user_msg["content"],
            "gold_json": gold_msg["content"],
            "raw_output": raw_output,
        })
        print(f"[{i + 1}/{len(rows)}] generated {len(raw_output)} chars")

    return results


@app.local_entrypoint()
def main():
    results = generate.remote()
    out_path = _REPO_ROOT / "finetune" / "eval_outputs.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Wrote {len(results)} generations to {out_path}")
