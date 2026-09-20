#!/usr/bin/env bash
# Overnight, resumable experiment queue for the laptop. Every step skips itself
# if its output already exists, so the script can be re-run after an interruption.
# Ollama must already be serving (2 slots, 8K ctx). One model, sequential steps.
#
#   ./scripts/night_queue.sh            # run everything
#   STEPS="judge1 js" ./scripts/night_queue.sh   # run a subset
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export RV="${RV:-$HOME/Documents/university/Real-Vuln-Benchmark}"
export DEEPGUARD_OPENAI_BASE_URL="${DEEPGUARD_OPENAI_BASE_URL:-http://localhost:11434/v1}"
export DEEPGUARD_OPENAI_API_KEY="${DEEPGUARD_OPENAI_API_KEY:-ollama}"
export DEEPGUARD_OPENAI_MODEL="${DEEPGUARD_OPENAI_MODEL:-qwen2.5-coder:7b}"
export DEEPGUARD_REQUEST_TIMEOUT="${DEEPGUARD_REQUEST_TIMEOUT:-300}"
export DEEPGUARD_BUDGET_CAP=100
LOGS="$HOME/Documents/university/deepguard-runs/logs"; mkdir -p "$LOGS"
STEPS="${STEPS:-wait judge1 judgeM verify1 js variance score}"
PY8="realvuln-pythonssti realvuln-intentionally-vulnerable-python-application realvuln-insecure-web realvuln-dsvw realvuln-python-insecure-app realvuln-vulnerable-api realvuln-vulnerable-tornado-app realvuln-damn-vulnerable-flask-application"
JS3="realvuln-vuln-node-express realvuln-dvna realvuln-node-api-goat"

ts() { date +%H:%M:%S; }
step() { echo "[$(ts)] === $1 ==="; }
have() { case " $STEPS " in *" $1 "*) return 0;; *) return 1;; esac; }

cd "$ROOT"
if have wait; then
  step "wait for any running zero-shot batch"
  while pgrep -f zero_shot_baseline.py >/dev/null; do sleep 60; done
fi

if have judge1; then
  step "judge, single-select, on deepguard-qwen7b"
  python3 scripts/realvuln_judge.py --slug deepguard-qwen7b --out-slug deepguard-qwen7b-judge1 \
    --select-mode single --repos $PY8 > "$LOGS/judge1.log" 2>&1; tail -3 "$LOGS/judge1.log"
fi
if have judgeM; then
  step "judge, multi-select, on deepguard-qwen7b"
  python3 scripts/realvuln_judge.py --slug deepguard-qwen7b --out-slug deepguard-qwen7b-judgeM \
    --select-mode multi --repos $PY8 > "$LOGS/judgeM.log" 2>&1; tail -3 "$LOGS/judgeM.log"
fi
if have verify1; then
  step "verifier on judge1 output"
  python3 scripts/realvuln_judge.py --slug deepguard-qwen7b-judge1 --out-slug deepguard-qwen7b-judge1-verify \
    --mode verify --repos $PY8 > "$LOGS/verify1.log" 2>&1; tail -3 "$LOGS/verify1.log"
fi
if have js; then
  step "DeepGuard sweep on first JS repos (incl. DVNA), current pipeline with quote/snap"
  SLUG=deepguard-qwen7b-js LANGS=js,ts ./scripts/realvuln_run.sh $JS3 > "$LOGS/js-batch1.log" 2>&1; tail -4 "$LOGS/js-batch1.log"
fi
if have variance; then
  step "run-to-run variance: 3 runs of python-multi-vuln with the current pipeline"
  for i in 1 2 3; do
    out="reports/variance/python-multi-vuln/run$i"
    if ls "$out"/scan-*.json >/dev/null 2>&1; then echo "  run$i exists, skipping"; continue; fi
    mkdir -p "$out"
    ./deepguard scan --path test-samples/python-multi-vuln --languages python --output "$out" \
      > "$LOGS/variance-run$i.log" 2>&1 || echo "  run$i FAILED (see log)"
    grep -E "Findings:|Duration:|line snapping" "$LOGS/variance-run$i.log" | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-120
  done
fi
if have score; then
  step "score everything"
  for slug in zeroshot-qwen7b deepguard-qwen7b-judge1 deepguard-qwen7b-judgeM deepguard-qwen7b-judge1-verify deepguard-qwen7b-js; do
    python3 scripts/realvuln_report.py "$slug" > "$LOGS/report-$slug.log" 2>&1 && grep -E "^=== |$slug @conf>=0.5" "$LOGS/report-$slug.log" | head -4
  done
  python3 scripts/realvuln_stats.py --slugs deepguard-qwen7b zeroshot-qwen7b deepguard-qwen7b-judge1 deepguard-qwen7b-judgeM deepguard-qwen7b-judge1-verify \
    --pairs deepguard-qwen7b:zeroshot-qwen7b deepguard-qwen7b:deepguard-qwen7b-judge1 deepguard-qwen7b-judge1:deepguard-qwen7b-judgeM deepguard-qwen7b-judge1:deepguard-qwen7b-judge1-verify \
    --repos $PY8 > "$LOGS/stats.log" 2>&1; tail -20 "$LOGS/stats.log"
fi
step "queue finished"
