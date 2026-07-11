#!/usr/bin/env bash
# Publish the fine-tuned mark2-report model to Ollama's public registry.
#
# One-time prerequisites (not done by this script):
#   - An ollama.com account.
#   - That account authorized for this machine's Ollama key: run `ollama signin`
#     once (opens a browser link to link ~/.ollama/id_ed25519.pub to your account).
#
# Usage:
#   ./finetune/publish_model.sh <namespace> [tag]
#
# Example:
#   ./finetune/publish_model.sh pseudocoder204 latest
#   -> publishes as pseudocoder204/mark2-report:latest

set -euo pipefail

NAMESPACE="${1:?Usage: $0 <ollama.com namespace> [tag]}"
TAG="${2:-latest}"
MODEL_NAME="${NAMESPACE}/mark2-report:${TAG}"

cd "$(dirname "$0")"

echo "Building local model from finetune/Modelfile..."
ollama create "${MODEL_NAME}" -f Modelfile

echo "Pushing ${MODEL_NAME} to ollama.com..."
ollama push "${MODEL_NAME}"

echo "Done. Others can now run: ollama pull ${MODEL_NAME}"
