"""FinetuneGuideTriage.txt PHASE 5 escalation — train a bigger-base multi-turn
triage model after BOTH the 3B multi-turn and 3B single-shot variants failed
the Step 14 A/B floor against _fallback_order (2026-07-12 runs: 0.824 and
0.843 mean intra-tier tau vs a 0.882 fallback baseline — though see the
eval-split fix below, which changes that fallback number).

Before this run, the 90/10 split (export_triage_trainset._stratify_split)
was found to under-represent the "gold disagrees with fallback" hard cases
in eval by chance (eval-only fallback-vs-gold tau was 0.882 vs 0.693 across
the full 303-row corpus) — the split now also stratifies on
_gold_differs_from_fallback, so the comparison in this run is against a
representative eval slice, not an artificially easy one.

Fork of train_triage_modal.py: same multi-turn corpus (train_triage.jsonl /
eval_triage.jsonl, re-exported after the split fix), same LoRA
hyperparameters, but BASE_MODEL bumped to Qwen2.5-7B-Instruct-bnb-4bit and a
distinct app/volume (mark2-triage-lora-7b-out) so it doesn't collide with the
3B multi-turn or single-shot adapters. Bumped to an A100-80GB — a 7B model in
4-bit plus LoRA optimizer states plus a 24576-token context (this corpus's
worst-case multi-turn trace) is tighter than the 3B's 40GB fit comfortably.

Usage:
    modal run finetune/train_triage_modal_7b.py
"""

import pathlib

import modal

app = modal.App("mark2-triage-lora-7b")

volume = modal.Volume.from_name("mark2-triage-lora-7b-out", create_if_missing=True)

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
    .add_local_file(str(_REPO_ROOT / "finetune" / "train_triage.jsonl"), "/root/train.jsonl", copy=True)
    .add_local_file(str(_REPO_ROOT / "finetune" / "eval_triage.jsonl"), "/root/eval.jsonl", copy=True)
)

BASE_MODEL = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
# Same token-length distribution as the 3B run, since Qwen2.5 shares one
# tokenizer across sizes. Same headroom margin as the 3B multi-turn trainer.
MAX_SEQ_LENGTH = 24576
OUTPUT_DIR = "/output"


@app.function(image=image, gpu="A100-80GB", volumes={OUTPUT_DIR: volume}, timeout=21600)
def train():
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import train_on_responses_only
    from datasets import load_dataset
    from trl import SFTConfig, SFTTrainer

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )

    # Same r=16 config as the 3B runs.
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        use_gradient_checkpointing="unsloth",
    )

    if tokenizer.eos_token not in tokenizer.get_vocab():
        print(
            f"WARNING: tokenizer.eos_token={tokenizer.eos_token!r} not in vocab; "
            "forcing to '<|im_end|>' (Qwen2.5 ChatML eos token)"
        )
        tokenizer.eos_token = "<|im_end|>"

    dataset = load_dataset(
        "json",
        data_files={"train": "/root/train.jsonl", "eval": "/root/eval.jsonl"},
    )

    def to_text(example):
        return {
            "text": tokenizer.apply_chat_template(
                example["messages"],
                tools=example.get("tools"),
                tokenize=False,
                add_generation_prompt=False,
            )
        }

    dataset = dataset.map(to_text, remove_columns=dataset["train"].column_names)

    sft_config = SFTConfig(
        output_dir=f"{OUTPUT_DIR}/checkpoints",
        dataset_text_field="text",
        max_length=MAX_SEQ_LENGTH,
        eos_token=tokenizer.eos_token,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        # Same reasoning as train_triage_modal.py: a single longest-eval-
        # example forward pass materializes a big fp32 logits tensor at this
        # max seq length; keep both batch sizes at 1 to bound memory to one
        # sequence at a time (7B has less headroom than 3B despite the
        # bigger GPU tier).
        per_device_eval_batch_size=1,
        eval_accumulation_steps=1,
        num_train_epochs=3,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        bf16=True,
        logging_steps=5,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        report_to="none",
    )

    if sft_config.eos_token not in tokenizer.get_vocab():
        sft_config.eos_token = tokenizer.eos_token

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset["train"],
        eval_dataset=dataset["eval"],
        args=sft_config,
    )

    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    result = trainer.train()
    print("train result:", result)
    print("eval log history:", trainer.state.log_history)

    adapter_dir = f"{OUTPUT_DIR}/triage-7b-lora"
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)
    volume.commit()

    return trainer.state.log_history


@app.local_entrypoint()
def main():
    log_history = train.remote()
    import json
    print(json.dumps(log_history, indent=2))
