#!/usr/bin/env bash
# Zero-shot (no-pipeline) control on RealVuln repos: same model, whole files,
# one minimal prompt each. Produces DeepGuard-shaped reports, converts them
# with the adapter, and scores them with the official RealVuln scorer, so the
# numbers sit in the same table as the DeepGuard runs.
#
# Usage:
#   RV=~/Documents/university/Real-Vuln-Benchmark SLUG=zeroshot-qwen7b \
#   DEEPGUARD_OPENAI_BASE_URL=http://localhost:11434/v1 DEEPGUARD_OPENAI_API_KEY=ollama \
#   DEEPGUARD_OPENAI_MODEL=qwen2.5-coder:7b ./scripts/realvuln_zeroshot.sh [repo ...]
#
# Repos already holding a report under reports/realvuln/$SLUG/ are skipped, so an
# interrupted batch resumes where it stopped.
# NO_SCORE=1 scans and converts without scoring (keeps a test set unscored).
set -euo pipefail
RV="${RV:?set RV to the Real-Vuln-Benchmark checkout}"
SLUG="${SLUG:-zeroshot}"
MODEL="${DEEPGUARD_OPENAI_MODEL:?set DEEPGUARD_OPENAI_MODEL}"
GT_DIR="${GT_DIR:-ground-truth}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/reports/realvuln/$SLUG"; mkdir -p "$OUT"

REPOS=("$@")
[ ${#REPOS[@]} -eq 0 ] && REPOS=($(ls "$RV/ground-truth" | grep '^realvuln-'))

for repo in "${REPOS[@]}"; do
  src="$RV/repos/$repo"
  [ -d "$src" ] || { echo "skip $repo (not cloned)"; continue; }
  report="$OUT/$repo/scan.json"
  if [ -f "$report" ]; then
    echo "=== $repo === (already done, skipping)"
  else
    echo "=== $repo ==="
    python3 "$ROOT/scripts/zero_shot_baseline.py" --bench-dir "$src" --lang py \
      --model "$MODEL" --output "$report" 2>&1 | grep -E "files, model=|Done|FAILED|skipped" || true
  fi
  python3 "$ROOT/scripts/realvuln_adapter.py" "$report" "$src" "$RV/scan-results/$repo/$SLUG/results.json" \
    || { echo "  ADAPTER FAILED for $repo - continuing"; continue; }
  [ "${NO_SCORE:-0}" = 1 ] || (cd "$RV" && python3 score.py --repo "$repo" --scanner "$SLUG" --gt-dir "$GT_DIR" | grep -E "^$SLUG" || true)
done
[ "${NO_SCORE:-0}" = 1 ] && exit 0

echo; echo "Aggregate (micro) over scored repos:"
python3 - "$RV" "$SLUG" "$GT_DIR" <<'PY'
import sys, glob, json
rv, slug, gtdir = sys.argv[1:4]
sys.path.insert(0, rv)
from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard
fam = json.load(open(f"{rv}/config/cwe-families.json"))
tp = fp = fn = tn = 0; n = 0
for res in sorted(glob.glob(f"{rv}/scan-results/realvuln-*/{slug}/results.json")):
    repo = res.split("/")[-3]
    gt = load_ground_truth(f"{rv}/{gtdir}/{repo}/ground-truth.json")
    findings = get_parser(slug).parse(res)
    if gtdir.endswith("ground-truth-inscope"):
        cw = set(json.load(open(f"{rv}/{gtdir}/in-scope-cwes.json")))
        findings = [x for x in findings if x.cwe in cw]
    card = compute_scorecard(repo, slug, "", match_findings(findings, gt), fam)
    tp += card.tp; fp += card.fp; fn += card.fn; tn += card.tn; n += 1
p = tp/(tp+fp) if tp+fp else 0; r = tp/(tp+fn) if tp+fn else 0
f1 = 2*p*r/(p+r) if p+r else 0; f2 = 5*p*r/(4*p+r) if p+r else 0
print(f"repos={n} TP={tp} FP={fp} FN={fn} TN={tn}  Prec={p:.3f} Rec={r:.3f} F1={f1:.3f} F2={f2*100:.1f}")
PY
