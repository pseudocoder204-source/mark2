"""Step 15 (FinetuneGuide.txt PHASE 6) — merge the report-LoRA adapter into the
base model and export to GGUF, quantized Q8_0, ready for `ollama create`.

Runs on Modal (same GPU/pinned-package stack as train_modal.py / eval_modal.py)
because merging + llama.cpp GGUF conversion needs the same CUDA/bnb stack used
for training, and Unsloth's save_pretrained_gguf clones+cmake-builds llama.cpp
itself (needs git/cmake/build-essential, added to the image below).

NOTE: Q4_K_M was tried first and produced garbled, wrong-schema, wrong-language
output for this specific 3B LoRA fine-tune, even though the LoRA merge and
HF->GGUF conversion steps are both correct in isolation (verified by comparing
the merged 16-bit checkpoint's direct output against the quantized GGUF's
output for the same input via debug_merged.py). Q8_0 reproduces the merged
model's output exactly and is what's actually shipped, at the cost of ~3.3GB
vs ~1.9GB on disk.

Usage:
    modal run finetune/export_modal.py
    # writes finetune/report-3b-q8_0.gguf locally
"""

import pathlib

import modal

app = modal.App("mark2-report-lora-export")

volume = modal.Volume.from_name("mark2-report-lora-out", create_if_missing=False)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git", "cmake", "build-essential", "curl")
    .pip_install(
        # Same pinned stack as train_modal.py / eval_modal.py — unpinned
        # installs can drift onto an incompatible unsloth/trl/transformers combo.
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
)

ADAPTER_DIR = "/output/report-3b-lora"
GGUF_OUT_DIR = "/output/report-3b-gguf"
MAX_SEQ_LENGTH = 4096


@app.function(
    image=image,
    gpu="A10G",
    volumes={"/output": volume},
    timeout=3600,
)
def export_gguf():
    # Unsloth must be imported before trl/transformers/peft — its patcher hooks
    # those modules at import time.
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=ADAPTER_DIR,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )

    # Merges the LoRA adapter into the base weights (dequantized to fp16
    # internally), converts to GGUF via llama.cpp, and quantizes to Q8_0.
    model.save_pretrained_gguf(
        GGUF_OUT_DIR,
        tokenizer,
        quantization_method="q8_0",
    )
    volume.commit()

    import os
    files = os.listdir(GGUF_OUT_DIR)
    print("GGUF export dir contents:", files)
    return files


@app.local_entrypoint()
def main():
    files = export_gguf.remote()
    print("Exported files on volume:", files)
    print(
        "Pull down with:\n"
        f"  modal volume get mark2-report-lora-out report-3b-gguf {_REPO_ROOT / 'finetune' / 'report-3b-gguf'}"
    )
