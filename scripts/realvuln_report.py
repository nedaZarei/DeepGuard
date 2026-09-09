#!/usr/bin/env python3
"""
Compare a DeepGuard RealVuln run against the shipped baselines, restricted to the
repos the run has actually scored, on both full and in-scope ground truth and at
several confidence thresholds (DeepGuard keeps confidence in extra.metadata).

Usage: RV=/path/to/Real-Vuln-Benchmark python3 scripts/realvuln_report.py deepguard-qwen7b
Writes reports/evaluation-metrics/realvuln-<slug>.json
"""
import glob, json, os, sys
RV = os.environ.get("RV") or sys.exit("set RV")
slug = sys.argv[1] if len(sys.argv) > 1 else "deepguard"
sys.path.insert(0, RV)
from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

fam = json.load(open(f"{RV}/config/cwe-families.json"))
INSCOPE_CWES = set(json.load(open(f"{RV}/ground-truth-inscope/in-scope-cwes.json")))
BASELINES = ["sonarqube", "semgrep", "snyk", "gemma4-31b-agentic-v1",
             "gemini-3.5-flash-agentic-v1", "claude-opus-5-cc-agentic-v1", "gpt-5.5-agentic-v1"]
THRESHOLDS = [0.5, 0.7, 0.8, 0.9]

repos = sorted(os.path.basename(os.path.dirname(os.path.dirname(p)))
               for p in glob.glob(f"{RV}/scan-results/realvuln-*/{slug}/results.json"))
if not repos:
    sys.exit(f"no results for {slug}")

# A scan whose API calls partly failed produced fewer findings than a clean run,
# so its recall is understated. Surface that instead of averaging it in silently.
REPORT_ROOT = os.path.join(os.path.dirname(__file__), "..", "reports/realvuln", slug)
incomplete = {}
for repo in repos:
    scans = sorted(glob.glob(os.path.join(REPORT_ROOT, repo, "scan-*.json")))
    if not scans:
        continue
    meta = json.load(open(scans[-1])).get("scan_metadata", {})
    a = meta.get("analysis")
    if a is None:
        incomplete[repo] = "unknown (scan predates completeness tracking)"
    elif a.get("failed"):
        incomplete[repo] = f"{a['failed']}/{a['attempted']} analyses failed"
if incomplete:
    print("WARNING - incomplete scans, recall understated for these repos:")
    for r, why in incomplete.items():
        print(f"  {r}: {why}")
    print()

def conf_of(f):
    return f.metadata.get("confidence") if hasattr(f, "metadata") and isinstance(f.metadata, dict) else None

def load_findings(path, parser_slug):
    return get_parser(parser_slug).parse(path)

def metrics(cards):
    tp = sum(c.tp for c in cards); fp = sum(c.fp for c in cards)
    fn = sum(c.fn for c in cards); tn = sum(c.tn for c in cards)
    p = tp/(tp+fp) if tp+fp else 0; r = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p*r/(p+r) if p+r else 0; f2 = 5*p*r/(4*p+r) if p+r else 0
    return dict(TP=round(tp,1), FP=round(fp,1), FN=round(fn,1), TN=round(tn,1),
                precision=round(p,4), recall=round(r,4), f1=round(f1,4), f2_score=round(f2*100,1))

def score(scanner, gt_dir, conf_min=None):
    inscope = gt_dir.endswith("inscope"); cards = []; per_repo = {}
    for repo in repos:
        files = [f for f in sorted(glob.glob(f"{RV}/scan-results/{repo}/{scanner}/*.json"))
                 if not f.endswith(".metrics.json")]
        if not files:
            continue
        gt_path = f"{RV}/{gt_dir}/{repo}/ground-truth.json"
        run_cards = []
        for f in files:
            fs = load_findings(f, scanner)
            if conf_min is not None:
                # DeepGuard adapter stores confidence in extra.metadata; SemgrepParser
                # does not surface it, so re-read the raw file for the filter.
                raw = json.load(open(f))["results"]
                def conf(r):
                    c = r.get("extra", {}).get("metadata", {}).get("confidence")
                    return c if isinstance(c, (int, float)) else 1.0  # non-DeepGuard files: keep
                keep = set()
                for r in raw:
                    if conf(r) >= conf_min:
                        cw = r.get("extra", {}).get("metadata", {}).get("cwe", [])
                        cw = [cw] if isinstance(cw, str) else cw
                        for c in cw:
                            keep.add((r["path"].lstrip("./"), r["start"]["line"], c.split(":")[0]))
                fs = [x for x in fs if (x.file, x.line, x.cwe) in keep]
            if inscope:
                fs = [x for x in fs if x.cwe in INSCOPE_CWES]
            run_cards.append(compute_scorecard(repo, scanner, "", match_findings(fs, load_ground_truth(gt_path)), fam))
        # mean over runs for multi-run agentic baselines
        k = len(run_cards)
        class C: pass
        c = C(); c.tp = sum(x.tp for x in run_cards)/k; c.fp = sum(x.fp for x in run_cards)/k
        c.fn = sum(x.fn for x in run_cards)/k; c.tn = sum(x.tn for x in run_cards)/k
        cards.append(c); per_repo[repo] = dict(TP=c.tp, FP=c.fp, FN=c.fn)
    return metrics(cards), per_repo

out = {"slug": slug, "repos": repos, "line_tolerance": 10,
       "incomplete_scans": incomplete, "full": {}, "in_scope": {}}
print(f"Repos scored by {slug}: {len(repos)}\n")
for gt_label, gt_dir in (("full", "ground-truth"), ("in_scope", "ground-truth-inscope")):
    print(f"=== {gt_label} ground truth, same {len(repos)} repos ===")
    print(f"{'scanner':<36}{'F1':>7}{'F2':>7}{'Prec':>7}{'Rec':>7}{'TP':>7}{'FP':>7}{'FN':>7}")
    rows = []
    for b in BASELINES:
        m, _ = score(b, gt_dir); rows.append((b, m)); out[gt_label][b] = m
    for t in THRESHOLDS:
        m, per = score(slug, gt_dir, conf_min=t); name = f"{slug} @conf>={t}"
        rows.append((name, m)); out[gt_label][name] = m
        if t == 0.5: out[gt_label][f"{slug}_per_repo"] = per
    for name, m in rows:
        print(f"{name:<36}{m['f1']:>7.3f}{m['f2_score']:>7.1f}{m['precision']:>7.3f}{m['recall']:>7.3f}{m['TP']:>7}{m['FP']:>7}{m['FN']:>7}")
    print()
dst = os.path.join(os.path.dirname(__file__), "..", f"reports/evaluation-metrics/realvuln-{slug}.json")
json.dump(out, open(dst, "w"), indent=2); print("saved", os.path.normpath(dst))
