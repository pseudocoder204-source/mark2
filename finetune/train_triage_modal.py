"""Step 9-10 (notes/FinetuneGuideTriage.txt PHASE 4) — QLoRA training on Modal
for the triage model.

Fork of finetune/train_modal.py (the report model's Modal trainer). Same base
model, same GPU tier, same LoRA hyperparameters — the only things that change
are: the app/volume names (so this doesn't clobber the report model's Modal
state), which JSONL files get baked into the image, and MAX_SEQ_LENGTH, which
has to be re-measured because triage examples carry multi-turn tool-call
traces (lookup_cves results inlined verbatim) that run far longer than a
single report completion.

Usage:
    modal run finetune/train_triage_modal.py

Pulls train_triage.jsonl / eval_triage.jsonl (Step 7/8 output) into the
image, trains Qwen2.5-3B-Instruct-bnb-4bit with the same QLoRA config as the
report model, evaluates each epoch, and keeps the checkpoint with the lowest
eval loss. The LoRA adapter is written to a Modal Volume
(mark2-triage-lora-out) so it survives after the container exits — pull it
down with:

    modal volume get mark2-triage-lora-out triage-3b-lora ./finetune/triage-3b-lora
"""

import pathlib

import modal

app = modal.App("mark2-triage-lora")

volume = modal.Volume.from_name("mark2-triage-lora-out", create_if_missing=True)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        # Pinned to the exact combo validated for the report model
        # (finetune/requirements.txt / train_modal.py) — unpinned installs
        # can drift onto an incompatible unsloth/trl/transformers combo.
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

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
# Report model used 4096 (fits a single report completion). Triage examples
# include inlined lookup_cves tool-result turns (up to 25 CVE records per
# call, per export_triage_trainset._shrink_tool_content's cap) and can chain
# up to 3 escalations in one trace, so the max token length is much larger.
# Set well above the measured max so no training example gets silently truncated.
MAX_SEQ_LENGTH = 24576
OUTPUT_DIR = "/output"


@app.function(image=image, gpu="A100-40GB", volumes={OUTPUT_DIR: volume}, timeout=14400)
def train():
    # Unsloth must be imported before trl/transformers/peft — its patcher
    # hooks those modules at import time (same requirement as train_modal.py).
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

    # Same r=16 config as the report model.
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

    # Same eos_token corruption guard as train_modal.py — get_peft_model
    # patches tokenizer.eos_token to a placeholder not in the vocab on this
    # environment; force it back to Qwen2.5's real ChatML eos token.
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
        # Chat-template render must include the "tools" block (the lookup_cves
        # schema) exactly as export_triage_trainset.py wrote it, or the
        # <tools> XML the model is trained to expect at inference won't match
        # what it's actually shown here.
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
        # Explicit (default is 8, not train's batch_size=1): a single
        # longest-eval-example forward pass materializes a
        # seq_len * vocab_size fp32 logits tensor that's already large at
        # this corpus's max token length — eval_batch_size>1 stacks that per
        # extra sequence and blows through the GPU's memory (hit in practice:
        # OOM at the first epoch-end eval after training itself completed
        # cleanly). Pinning both to 1 keeps memory to one sequence's worth
        # at a time.
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

    # Mask system/user turns (script_findings-stripped table + tool results,
    # which render as a "user" role wrapped in <tool_response>...</tool_response>
    # per Qwen2.5's chat template) so loss is computed only on assistant turns.
    # Because EVERY assistant turn (tool_call turns AND the final
    # {"priority_order": [...]} turn) is delimited by the same
    # "<|im_start|>assistant\n" marker, this single instruction/response pair
    # unmasks both — the model must learn to produce the tool calls, not just
    # the final answer.
    trainer = train_on_responses_only(
        trainer,
        instruction_part="<|im_start|>user\n",
        response_part="<|im_start|>assistant\n",
    )

    result = trainer.train()
    print("train result:", result)
    print("eval log history:", trainer.state.log_history)

    adapter_dir = f"{OUTPUT_DIR}/triage-3b-lora"
    model.save_pretrained(adapter_dir)
    tokenizer.save_pretrained(adapter_dir)
    volume.commit()

    return trainer.state.log_history


@app.local_entrypoint()
def main():
    log_history = train.remote()
    import json
    print(json.dumps(log_history, indent=2))
