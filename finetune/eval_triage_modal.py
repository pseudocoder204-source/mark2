"""Step 11-14 (notes/FinetuneGuideTriage.txt PHASE 5) — generate triage outputs
from BOTH the tuned mark2-triage LoRA adapter and the stock (untuned) base
model over the held-out finetune/eval_triage.jsonl inputs, with REAL
multi-turn tool calling.

Unlike the report model's eval_modal.py (single-shot, no tools), triage
inference is a loop: the model may emit a <tool_call>lookup_cves</tool_call>,
which must be executed and fed back before the model continues. Executing
lookup_cves needs the actual local vulnerability_cache.db (nmap_parser.
fetch_cves_from_local_cache) — the exact same cache the gold labels in
eval_triage.jsonl were drafted against (label_triage_batch.py) and that
run_triage/tools.lookup_cves use at real inference time. Rather than ship the
3GB+ cache into the Modal image, this script keeps the GPU container warm
(modal.Cls with @modal.enter, one instance per variant) and drives the
multi-turn loop from the LOCAL process: each turn calls .generate.remote(...)
for the next assistant turn, then, if that turn is a tool call, executes
tools.lookup_cves.func(cpe) locally (real cache, real code, no
reimplementation) and appends the tool turn before asking for the next turn.
This mirrors run_triage's own loop (agent.py:390-435) turn-for-turn, including
the escalation-budget/in-scope gating and the "no tool_call -> final text"
break condition.

Usage:
    modal run finetune/eval_triage_modal.py
    # writes finetune/eval_triage_outputs.json locally
"""

import json
import pathlib
import re
import sys

import modal

app = modal.App("mark2-triage-lora-eval")

volume = modal.Volume.from_name("mark2-triage-lora-out", create_if_missing=False)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install(
        # Same pinned stack as train_triage_modal.py.
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

BASE_MODEL = "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
MAX_SEQ_LENGTH = 24576  # must match train_triage_modal.py so eval prompts aren't truncated
ADAPTER_DIR = "/output/triage-3b-lora"
MAX_NEW_TOKENS = 1024
_MAX_ESCALATIONS = 3  # kept in sync with agent.py's constant; verified equal at runtime below

_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


@app.cls(image=image, gpu="A10G", volumes={"/output": volume}, timeout=1800, scaledown_window=600)
class TriageModel:
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
    def generate(self, messages, tools):
        prompt = self.tokenizer.apply_chat_template(
            messages, tools=tools, tokenize=False, add_generation_prompt=True,
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


def _parse_tool_call(raw_text: str):
    """Returns (name, args_dict) for the first <tool_call> block, or None."""
    m = _TOOL_CALL_RE.search(raw_text)
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
        return obj["name"], obj.get("arguments", {})
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _run_multiturn(model_handle, system_msg, user_msg, tools, table):
    """Mirrors run_triage's loop (agent.py:390-435) but drives generation via
    a warm Modal container instead of a bound LangChain LLM, and executes
    lookup_cves locally against the real vulnerability_cache.db."""
    from tools import lookup_cves
    from export_triage_trainset import _shrink_tool_content

    valid_cpes = {f["cpe"] for f in table if f.get("cpe")}
    messages = [system_msg, user_msg]
    escalations_used = 0
    escalated_cpes = []
    turns_trace = []

    final_text = ""
    for _ in range(_MAX_ESCALATIONS + 1):
        raw = model_handle.generate.remote(messages, tools)
        parsed = _parse_tool_call(raw)
        if parsed is None:
            final_text = raw
            turns_trace.append({"role": "assistant", "content": raw})
            break

        name, args = parsed
        cpe = args.get("cpe")
        messages.append({
            "role": "assistant", "content": "",
            "tool_calls": [{"function": {"name": name, "arguments": args}}],
        })
        turns_trace.append({"role": "assistant", "tool_call": {"name": name, "args": args}})

        if escalations_used >= _MAX_ESCALATIONS or cpe not in valid_cpes:
            result = json.dumps({"error": "escalation denied: budget exhausted or cpe out of scope"})
        else:
            escalations_used += 1
            escalated_cpes.append(cpe)
            # Same cap export_triage_trainset._shrink_tool_content applies at
            # training time (nmap_parser.fetch_cves_from_local_cache has no
            # row cap and a contested cpe can return 400-1800+ CVE records,
            # blowing the context window across a multi-turn conversation).
            result = _shrink_tool_content(lookup_cves.func(cpe))
        messages.append({"role": "tool", "content": result})
        turns_trace.append({"role": "tool", "content": result})
    else:
        # Exhausted the loop budget still emitting tool calls — ask once more,
        # forcing a final answer, same recovery run_triage applies (agent.py:424-429).
        messages.append({
            "role": "user",
            "content": 'Stop calling tools. Respond with ONLY the JSON object '
                        '{"priority_order": [...]} now.',
        })
        final_text = model_handle.generate.remote(messages, tools)
        turns_trace.append({"role": "assistant", "content": final_text})

    return {
        "final_text": final_text,
        "escalations_used": escalations_used,
        "escalated_cpes": escalated_cpes,
        "trace": turns_trace,
    }


def _gold_from_record(rec):
    """Pull the gold trace's escalated cpes and final priority_order text
    straight out of the exported record — this IS the Opus-labeled gold
    (validated via _validate_triage_order before export)."""
    escalated = []
    final_text = None
    for m in rec["messages"][2:]:
        if m["role"] == "assistant" and m.get("tool_calls"):
            for tc in m["tool_calls"]:
                cpe = tc["function"]["arguments"].get("cpe")
                if cpe:
                    escalated.append(cpe)
        elif m["role"] == "assistant":
            final_text = m["content"]
    return {"final_text": final_text, "escalated_cpes": escalated}


@app.local_entrypoint()
def main():
    import agent  # local import so this only needs agent.py on the DRIVER, not the image
    assert agent._MAX_ESCALATIONS == _MAX_ESCALATIONS, (
        "eval_triage_modal._MAX_ESCALATIONS drifted from agent.py — update the constant above"
    )

    eval_path = _REPO_ROOT / "finetune" / "eval_triage.jsonl"
    rows = [json.loads(l) for l in eval_path.read_text().splitlines() if l.strip()]

    tuned = TriageModel(variant="tuned")
    stock = TriageModel(variant="stock")

    results = []
    for i, rec in enumerate(rows):
        system_msg, user_msg = rec["messages"][0], rec["messages"][1]
        table = json.loads(user_msg["content"])
        tools = rec.get("tools")
        gold = _gold_from_record(rec)

        tuned_out = _run_multiturn(tuned, system_msg, user_msg, tools, table)
        stock_out = _run_multiturn(stock, system_msg, user_msg, tools, table)

        results.append({
            "index": i,
            "ordered_facts_json": user_msg["content"],
            "gold": gold,
            "tuned": tuned_out,
            "stock": stock_out,
        })
        print(f"[{i + 1}/{len(rows)}] tuned_esc={tuned_out['escalations_used']} "
              f"stock_esc={stock_out['escalations_used']} gold_esc={len(gold['escalated_cpes'])}")

    out_path = _REPO_ROOT / "finetune" / "eval_triage_outputs.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Wrote {len(results)} rows to {out_path}")
