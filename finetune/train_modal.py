"""Steps 11-12 (FinetuneGuide.txt PHASE 4) — QLoRA training on Modal.

Runs the report-model LoRA fine-tune on a Modal GPU instead of the local
RTX 5060 (8GB, Blackwell/sm_120 — new hardware with no FA2 support yet).
Modal's A10G (24GB, proven CUDA stack) comfortably fits this 3B QLoRA job,
which the guide estimates at minutes-to-an-hour, well inside the $30/mo
free credit.

Usage:
    modal run finetune/train_modal.py

Pulls train.jsonl / eval.jsonl (Step 8/9 output) into the image, trains
Qwen2.5-3B-Instruct-bnb-4bit with the Step 11 QLoRA config, evaluates each
epoch, and keeps the checkpoint with the lowest eval loss (Step 12: "stop
when eval loss flattens or ticks up"). The LoRA adapter is written to a
Modal Volume (mark2-report-lora-out) so it survives after the container
exits — pull it down with:

    modal volume get mark2-report-lora-out report-3b-lora ./finetune/report-3b-lora
"""

import pathlib

import modal

app = modal.App("mark2-report-lora")

volume = modal.Volume.from_name("mark2-report-lora-out", create_if_missing=True)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        # Pinned to the exact combo validated locally (finetune/requirements.txt) —
        # unpinned installs re-resolve on every image build and can drift onto an
        # incompatible pairing (hit: unsloth's internal trl-source patcher throwing
        # IndexError against a newer trl/transformers combo pip picked at build time).
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
    .add_local_file(str(_REPO_ROOT / "finetune" / "train.jsonl"), "/root/train.jsonl", copy=True)
    .add_local_file(str(_REPO_ROOT / "finetune" / "eval.jsonl"), "/root/eval.jsonl", copy=True)
)

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
MAX_SEQ_LENGTH = 4096
OUTPUT_DIR = "/output"


@app.function(image=image, gpu="A10G", volumes={OUTPUT_DIR: volume}, timeout=3600)
def train():
    # Unsloth must be imported before trl/transformers/peft — its patcher hooks
    # those modules at import time. Importing trl first (as an earlier version of
    # this script did) left SFTTrainer's eos_token substitution half-wired: our
    # sft_config.eos_token was correctly '<|im_end|>' right after construction,
    # yet SFTTrainer.__init__ still rejected it as the literal placeholder
    # '<EOS_TOKEN>' — a symptom of Unsloth's patch not fully attaching.
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

    # r=16 is enough for a formatting+voice skill, not a knowledge task.
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

    # Guard against get_peft_model leaving tokenizer.eos_token set to a
    # placeholder ('<EOS_TOKEN>', not in the vocab) on this environment —
    # confirmed via logging that eos_token is correct right after
    # from_pretrained but wrong by the time SFTConfig is built, so the
    # corruption happens somewhere inside get_peft_model's patching.
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
                example["messages"], tokenize=False, add_generation_prompt=False
            )
        }

    dataset = dataset.map(to_text, remove_columns=dataset["train"].column_names)

    sft_config = SFTConfig(
        output_dir=f"{OUTPUT_DIR}/checkpoints",
        dataset_text_field="text",
        max_length=MAX_SEQ_LENGTH,
        # Explicit override: something in Unsloth's monkey-patching injects a
        # non-None "<EOS_TOKEN>" placeholder as SFTConfig's default eos_token on
        # this environment, which trl then rejects as not-in-vocab. Passing the
        # real value here wins over whatever default Unsloth patched in.
        eos_token=tokenizer.eos_token,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
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

    print(f"DEBUG: sft_config.eos_token after construction = {sft_config.eos_token!r}")
    if sft_config.eos_token not in tokenizer.get_vocab():
        print(f"DEBUG: overriding sft_config.eos_token -> {tokenizer.eos_token!r}")
        sft_config.eos_token = tokenizer.eos_token

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset["train"],
        eval_dataset=dataset["eval"],
        args=sft_config,
    )

    # Mask the prompt (system+user) so loss is computed on the assistant
    # completion only — the model should learn to generate the report,
    # not reproduce the findings table it was given.
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    result = trainer.train()
    print("train result:", result)
    print("eval log history:", trainer.state.log_history)

    adapter_dir = f"{OUTPUT_DIR}/report-3b-lora"
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)
    volume.commit()

    return trainer.state.log_history


@app.local_entrypoint()
def main():
    log_history = train.remote()
    import json
    print(json.dumps(log_history, indent=2))
