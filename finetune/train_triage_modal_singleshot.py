"""FinetuneGuideTriage.txt PHASE 5 fallback — train the SINGLE-SHOT triage
variant (table -> final JSON only, no tool-call turns) after the multi-turn
tuned model failed the Step 14 A/B floor (tuned intra-tier tau 0.824 <
fallback 0.882, 2026-07-12 eval run; see finetune/eval_triage_scores.json).

Fork of train_triage_modal.py: same base model and LoRA config, but a
different app/volume (mark2-triage-lora-singleshot-out) so it doesn't clobber
the multi-turn adapter, the single-shot JSONL files, and a much shorter
MAX_SEQ_LENGTH (no inlined tool-result turns to blow up the context).

Usage:
    modal run finetune/train_triage_modal_singleshot.py
"""

import pathlib

import modal

app = modal.App("mark2-triage-lora-singleshot")

volume = modal.Volume.from_name("mark2-triage-lora-singleshot-out", create_if_missing=True)

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
    .add_local_file(str(_REPO_ROOT / "finetune" / "train_triage_singleshot.jsonl"), "/root/train.jsonl", copy=True)
    .add_local_file(str(_REPO_ROOT / "finetune" / "eval_triage_singleshot.jsonl"), "/root/eval.jsonl", copy=True)
)

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
# Re-measured over train_triage_singleshot.jsonl + eval_triage_singleshot.jsonl
# (Qwen2.5 tokenizer, no tool schema) on 2026-07-12: p50=895, p90=1690,
# p95=1854, max=4122 (n=303). No inlined lookup_cves tool results here, so
# this is far shorter than the multi-turn set's 24576.
MAX_SEQ_LENGTH = 6144
OUTPUT_DIR = "/output"


@app.function(image=image, gpu="A10G", volumes={OUTPUT_DIR: volume}, timeout=7200)
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
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        per_device_eval_batch_size=2,
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

    # Single-shot records have exactly one assistant turn (the final JSON),
    # so this masks system/user and unmasks only that turn — no tool-call
    # turns exist in this variant to worry about unmasking separately.
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    result = trainer.train()
    print("train result:", result)
    print("eval log history:", trainer.state.log_history)

    adapter_dir = f"{OUTPUT_DIR}/triage-3b-lora-singleshot"
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)
    volume.commit()

    return trainer.state.log_history


@app.local_entrypoint()
def main():
    log_history = train.remote()
    import json
    print(json.dumps(log_history, indent=2))
