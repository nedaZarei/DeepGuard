#!/usr/bin/env bash
# Run DeepGuard on the RealVuln human-authored corpus (26 Python repos) and score it.
#
# Prereqs:
#   git clone https://github.com/kolega-ai/Real-Vuln-Benchmark.git $RV && cd $RV && pip install -e .
#   ls ground-truth | grep '^realvuln-' | xargs python3 clone_repos.py --repo
#   CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard
#
# Model: any OpenAI-compatible endpoint. Free option (Groq):
#   export DEEPGUARD_OPENAI_BASE_URL=https://api.groq.com/openai/v1
#   export DEEPGUARD_OPENAI_API_KEY=<groq key>
#   export DEEPGUARD_OPENAI_MODEL=llama-3.3-70b-versatile
#
# Usage: RV=/path/to/Real-Vuln-Benchmark SLUG=deepguard-llama70b ./scripts/realvuln_run.sh [repo ...]
set -euo pipefail
RV="${RV:?set RV to the Real-Vuln-Benchmark checkout}"
SLUG="${SLUG:-deepguard}"
BUDGET="${DEEPGUARD_BUDGET_CAP:-10}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/reports/realvuln/$SLUG"; mkdir -p "$OUT"

REPOS=("$@")
[ ${#REPOS[@]} -eq 0 ] && REPOS=($(ls "$RV/ground-truth" | grep '^realvuln-'))

for repo in "${REPOS[@]}"; do
  src="$RV/repos/$repo"
  [ -d "$src" ] || { echo "skip $repo (not cloned)"; continue; }
  echo "=== $repo ==="
  scan_out="$OUT/$repo"; mkdir -p "$scan_out"
  DEEPGUARD_BUDGET_CAP="$BUDGET" "$ROOT/deepguard" scan --path "$src" --languages python --output "$scan_out" \
    2>&1 | grep -E "Extracted|Findings:|Cost:|Duration:|ERR" || true
  report="$(ls -t "$scan_out"/scan-*.json 2>/dev/null | head -1)"
  [ -n "$report" ] || { echo "no report for $repo"; continue; }
  python3 "$ROOT/scripts/realvuln_adapter.py" "$report" "$src" "$RV/scan-results/$repo/$SLUG/results.json"
  (cd "$RV" && python3 score.py --repo "$repo" --scanner "$SLUG" | grep -E "^$SLUG" || true)
done

echo; echo "Aggregate (micro) over scored repos:"
python3 - "$RV" "$SLUG" <<'PY'
import sys, glob, json
rv, slug = sys.argv[1:3]
sys.path.insert(0, rv)
from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard
fam = json.load(open(f"{rv}/config/cwe-families.json"))
tp = fp = fn = tn = 0; n = 0
for res in sorted(glob.glob(f"{rv}/scan-results/realvuln-*/{slug}/results.json")):
    repo = res.split("/")[-3]
    gt = load_ground_truth(f"{rv}/ground-truth/{repo}/ground-truth.json")
    card = compute_scorecard(repo, slug, "", match_findings(get_parser(slug).parse(res), gt), fam)
    tp += card.tp; fp += card.fp; fn += card.fn; tn += card.tn; n += 1
p = tp/(tp+fp) if tp+fp else 0; r = tp/(tp+fn) if tp+fn else 0
f1 = 2*p*r/(p+r) if p+r else 0; f2 = 5*p*r/(4*p+r) if p+r else 0
print(f"repos={n} TP={tp} FP={fp} FN={fn} TN={tn}  Prec={p:.3f} Rec={r:.3f} F1={f1:.3f} F2={f2*100:.1f}")
PY
