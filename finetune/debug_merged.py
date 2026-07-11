"""Debug: does the MERGED 16-bit safetensors model (before GGUF conversion)
already exhibit the broken/base-model behavior, or did it break during the
HF->GGUF conversion / Q4_K_M quantization step?

Loads /output/report-3b-gguf (Unsloth's merged_16bit save, pre-GGUF) directly
via transformers and generates for eval row 0.
"""

import json
import pathlib

import modal

app = modal.App("mark2-report-debug-merged")

volume = modal.Volume.from_name("mark2-report-lora-out", create_if_missing=False)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        "torch==2.10.0",
        "transformers==5.5.0",
        "accelerate==1.14.0",
        "numpy==2.5.1",
    )
    .add_local_file(str(_REPO_ROOT / "finetune" / "eval.jsonl"), "/root/eval.jsonl", copy=True)
)

MERGED_DIR = "/output/report-3b-gguf"


@app.function(image=image, gpu="A10G", volumes={"/output": volume}, timeout=600)
def generate():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MERGED_DIR)
    model = AutoModelForCausalLM.from_pretrained(
        MERGED_DIR, torch_dtype=torch.bfloat16, device_map="cuda"
    )

    rows = [json.loads(l) for l in open("/root/eval.jsonl")]
    results = []
    for rec in rows[:4]:
        messages = [rec["messages"][0], rec["messages"][1]]
        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        out = model.generate(
            **inputs,
            max_new_tokens=2000,
            temperature=0.3,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id,
        )
        text = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        print(f"=== MERGED MODEL OUTPUT (row {rec.get('index', '?')}) ===")
        print(text)
        print()
        results.append(text)
    return results


@app.local_entrypoint()
def main():
    texts = generate.remote()
    for i, text in enumerate(texts):
        print(f"--- row {i} ---")
        print(text)
        print()
