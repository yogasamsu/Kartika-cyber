#!/usr/bin/env bash
# Menjalankan Ollama dengan model disimpan di SSD terenkripsi Prika-Tameng.
set -euo pipefail

# Sengaja tidak mewarisi OLLAMA_MODELS dari profil shell, yang mungkin masih
# menunjuk volume lain. Ganti lewat TAMENG_OLLAMA_MODELS bila perlu.
MODELS_DIR="${TAMENG_OLLAMA_MODELS:-/Volumes/Prika-Tameng/ollama-models}"

if [ ! -d "$MODELS_DIR" ]; then
  echo "Folder model tidak ditemukan: $MODELS_DIR" >&2
  echo "Pastikan SSD Prika terpasang dan volume Prika-Tameng sudah dibuka." >&2
  exit 1
fi

export OLLAMA_MODELS="$MODELS_DIR"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
export OLLAMA_FLASH_ATTENTION=1
export OLLAMA_KV_CACHE_TYPE=q8_0
# Satu model saja di memori supaya RAM 16 GB cukup untuk lab.
export OLLAMA_MAX_LOADED_MODELS=1
export OLLAMA_NUM_PARALLEL=1
# Konteks 8K cukup untuk ringkasan insiden; default 32K memboroskan RAM.
export OLLAMA_CONTEXT_LENGTH=8192
# Air-gapped: matikan fitur model cloud.
export OLLAMA_NO_CLOUD=1

exec /opt/homebrew/opt/ollama/bin/ollama serve
