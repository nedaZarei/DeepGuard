#!/usr/bin/env bash
# One-time setup on a shared Linux GPU box (e.g. 4x RTX 3090) for the RealVuln runs.
# Everything lives under $WORK (default ~/deepguard-work); nothing is installed
# system-wide and no sudo is needed. Ollama is run as a user process bound to
# localhost. Re-running this script is safe.
#
# Usage on the box:
#   bash beast_setup.sh                  # install + clone + pull models
#   MODELS="qwen3.5:9b gemma4:12b" bash beast_setup.sh
#   CUDA_VISIBLE_DEVICES=1,2,3 bash beast_setup.sh   # leave GPU 0 to its current user
#
# Afterwards, in one tmux session:
#   source $WORK/env.sh && ollama serve &          # once per session
#   cd $WORK/deep-guard && RV=$WORK/Real-Vuln-Benchmark SLUG=deepguard-<model> \
#     DEEPGUARD_OPENAI_MODEL=<model> ./scripts/realvuln_run.sh
set -euo pipefail

WORK="${WORK:-$HOME/deepguard-work}"
MODELS="${MODELS:-qwen2.5-coder:7b qwen2.5-coder:14b qwen3.5:9b gemma4:12b}"
DEEPGUARD_REPO="${DEEPGUARD_REPO:-https://github.com/nedaZarei/DeepGuard.git}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
mkdir -p "$WORK/bin" "$WORK/logs" "$WORK/ollama-models"

echo "== GPUs visible to this session =="
nvidia-smi --query-gpu=index,name,memory.used,memory.total --format=csv,noheader || true

# --- Ollama, user-local, no root -------------------------------------------
if [ ! -x "$WORK/bin/ollama" ]; then
  echo "== downloading ollama (linux amd64) =="
  curl -fsSL https://ollama.com/download/ollama-linux-amd64.tgz -o "$WORK/ollama.tgz"
  tar -xzf "$WORK/ollama.tgz" -C "$WORK" && rm "$WORK/ollama.tgz"
  # the tarball unpacks bin/ and lib/ under $WORK
fi
"$WORK/bin/ollama" --version

# --- Go (needed to build deepguard; skip if a recent go is already on PATH) --
if ! command -v go >/dev/null 2>&1 || ! go version | grep -qE 'go1\.(2[4-9]|[3-9][0-9])'; then
  echo "== installing user-local Go 1.24 =="
  curl -fsSL https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o "$WORK/go.tgz"
  rm -rf "$WORK/go" && tar -xzf "$WORK/go.tgz" -C "$WORK" && rm "$WORK/go.tgz"
fi

# --- env file to source in every session -------------------------------------
cat > "$WORK/env.sh" <<EOF
export WORK="$WORK"
export PATH="$WORK/bin:$WORK/go/bin:\$PATH"
export OLLAMA_MODELS="$WORK/ollama-models"
export OLLAMA_HOST="127.0.0.1:$OLLAMA_PORT"
export OLLAMA_NUM_PARALLEL="\${OLLAMA_NUM_PARALLEL:-8}"
export OLLAMA_CONTEXT_LENGTH="\${OLLAMA_CONTEXT_LENGTH:-8192}"
export OLLAMA_KEEP_ALIVE="\${OLLAMA_KEEP_ALIVE:-30m}"
export DEEPGUARD_OPENAI_BASE_URL="http://127.0.0.1:$OLLAMA_PORT/v1"
export DEEPGUARD_OPENAI_API_KEY="ollama"
export DEEPGUARD_REQUEST_TIMEOUT="300"
export DEEPGUARD_BUDGET_CAP="1000"
export DEEPGUARD_WORKER_COUNT="\${DEEPGUARD_WORKER_COUNT:-8}"
export RV="$WORK/Real-Vuln-Benchmark"
EOF
# shellcheck disable=SC1090
source "$WORK/env.sh"

# --- code + benchmark ---------------------------------------------------------
if [ ! -d "$WORK/deep-guard/.git" ]; then
  git clone -q "$DEEPGUARD_REPO" "$WORK/deep-guard"
else
  git -C "$WORK/deep-guard" pull -q --ff-only || true
fi
(cd "$WORK/deep-guard" && CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard && ./deepguard version | head -1)

if [ ! -d "$RV/.git" ]; then
  git clone -q --depth 1 https://github.com/kolega-ai/Real-Vuln-Benchmark.git "$RV"
fi
(cd "$RV" && pip3 install -q --user -e . >/dev/null 2>&1 || true
 ls ground-truth | grep '^realvuln-' | xargs python3 clone_repos.py --repo 2>&1 | grep -E "Done|failed" || true)
(cd "$WORK/deep-guard" && python3 scripts/realvuln_baselines.py >/dev/null 2>&1 && echo "in-scope ground truth ready")

# --- models -----------------------------------------------------------------
echo "== starting ollama to pull models =="
nohup "$WORK/bin/ollama" serve > "$WORK/logs/ollama-serve.log" 2>&1 &
sleep 4
for m in $MODELS; do
  echo "-- pulling $m"; "$WORK/bin/ollama" pull "$m" 2>&1 | tail -1
done
"$WORK/bin/ollama" list

cat <<EOF

Setup complete. Each session:
  source $WORK/env.sh
  tmux new -s dg
  ollama serve > \$WORK/logs/ollama-serve.log 2>&1 &
  cd \$WORK/deep-guard
  SLUG=deepguard-qwen7b DEEPGUARD_OPENAI_MODEL=qwen2.5-coder:7b ./scripts/realvuln_run.sh
  SLUG=deepguard-qwen7b-js LANGS=js,ts DEEPGUARD_OPENAI_MODEL=qwen2.5-coder:7b ./scripts/realvuln_run.sh <js repos>
Results land in \$WORK/deep-guard/reports/realvuln/<SLUG>/ ; copy that directory back to your laptop.
Throughput: 8 workers x 8 slots on 3-4 GPUs; raise OLLAMA_NUM_PARALLEL/DEEPGUARD_WORKER_COUNT if GPU util stays low.
EOF
