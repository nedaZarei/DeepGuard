#!/usr/bin/env python3
"""
Score the baselines RealVuln ships (Semgrep, Snyk, SonarQube, best agentic LLMs)
on the 26 human-authored repos, against two ground truths:
  full     : official RealVuln ground truth (leaderboard-comparable)
  in-scope : only the 9 vulnerability classes DeepGuard's Python templates cover

Also writes the in-scope ground truth to $RV/ground-truth-inscope/ so the same
`score.py --gt-dir` path can be used for DeepGuard.

Usage: RV=/path/to/Real-Vuln-Benchmark python3 scripts/realvuln_baselines.py
"""
import glob, json, os, sys
RV = os.environ.get("RV") or sys.exit("set RV")
sys.path.insert(0, RV)
from parsers import get_parser
from scorer.matcher import load_ground_truth, match_findings
from scorer.metrics import compute_scorecard

# GT vulnerability_class values grouped under DeepGuard's 9 Python templates
IN_SCOPE = {
    "sql_injection", "nosql_injection",
    "reflected_xss", "stored_xss", "dom_xss", "xss",
    "command_injection", "code_injection",
    "ssrf",
    "path_traversal", "arbitrary_file_write", "unrestricted_file_upload",
    "insecure_deserialization", "xxe",
    "missing_authentication", "broken_authentication", "missing_authorization",
    "broken_access_control", "idor", "missing_access_control", "missing_auth",
    "session_fixation", "session_management", "session_hijacking", "insecure_session",
    "weak_cryptography", "weak_hash", "insecure_random", "weak_prng",
    "insecure_randomness", "plaintext_password_storage",
}
BASELINES = ["semgrep", "snyk", "sonarqube", "gpt-5.5-agentic-v1",
             "claude-opus-5-cc-agentic-v1", "gemini-3.5-flash-agentic-v1", "gemma4-31b-agentic-v1"]

fam = json.load(open(f"{RV}/config/cwe-families.json"))
repos = sorted(os.path.basename(p) for p in glob.glob(f"{RV}/ground-truth/realvuln-*"))

# --- write in-scope GT ------------------------------------------------------
n_full = n_scope = 0
for repo in repos:
    gt = json.load(open(f"{RV}/ground-truth/{repo}/ground-truth.json"))
    n_full += sum(1 for x in gt["findings"] if x["is_vulnerable"])
    gt["findings"] = [x for x in gt["findings"] if x["vulnerability_class"] in IN_SCOPE]
    n_scope += sum(1 for x in gt["findings"] if x["is_vulnerable"])
    d = f"{RV}/ground-truth-inscope/{repo}"; os.makedirs(d, exist_ok=True)
    json.dump(gt, open(f"{d}/ground-truth.json", "w"), indent=2)
print(f"ground truth: full={n_full} vulns, in-scope={n_scope} vulns over {len(repos)} repos")

# CWEs that belong to in-scope classes. In in-scope mode scanner findings outside
# this set are dropped before matching, so a scanner is not penalised (FP) for
# reporting classes the in-scope GT deliberately excludes.
IN_SCOPE_CWES = set()
for repo in repos:
    for x in json.load(open(f"{RV}/ground-truth-inscope/{repo}/ground-truth.json"))["findings"]:
        IN_SCOPE_CWES.update(x["acceptable_cwes"])
json.dump(sorted(IN_SCOPE_CWES), open(f"{RV}/ground-truth-inscope/in-scope-cwes.json", "w"))
print(f"in-scope CWE set: {len(IN_SCOPE_CWES)} CWEs")

# --- score ------------------------------------------------------------------
def score(slug, gt_root):
    tp = fp = fn = tn = 0; n = 0
    inscope = gt_root.endswith("ground-truth-inscope")
    for repo in repos:
        # results.json for single-run scanners; run-N.json for agentic runs (mean over runs)
        files = [f for f in sorted(glob.glob(f"{RV}/scan-results/{repo}/{slug}/*.json"))
                 if not f.endswith(".metrics.json")]
        if not files:
            continue
        gt_path = f"{gt_root}/{repo}/ground-truth.json"
        cards = []
        for f in files:
            findings = get_parser(slug).parse(f)
            if inscope:
                findings = [x for x in findings if x.cwe in IN_SCOPE_CWES]
            cards.append(compute_scorecard(repo, slug, "", match_findings(findings, load_ground_truth(gt_path)), fam))
        k = len(cards)
        tp += sum(c.tp for c in cards)/k; fp += sum(c.fp for c in cards)/k
        fn += sum(c.fn for c in cards)/k; tn += sum(c.tn for c in cards)/k; n += 1
    p = tp/(tp+fp) if tp+fp else 0; r = tp/(tp+fn) if tp+fn else 0
    f1 = 2*p*r/(p+r) if p+r else 0; f2 = 5*p*r/(4*p+r) if p+r else 0
    return dict(repos=n, TP=round(tp,1), FP=round(fp,1), FN=round(fn,1), TN=round(tn,1), precision=round(p,4), recall=round(r,4), f1=round(f1,4), f2_score=round(f2*100,1))

out = {"dataset": "RealVuln human-authored subset (26 Python repos)", "line_tolerance": 10,
       "full": {}, "in_scope": {}}
print(f"\n{'scanner':<32}{'GT':>9}{'F1':>7}{'F2':>7}{'Prec':>7}{'Rec':>7}{'TP':>6}{'FP':>6}{'FN':>6}")
for slug in BASELINES:
    for label, root in (("full", f"{RV}/ground-truth"), ("in_scope", f"{RV}/ground-truth-inscope")):
        m = score(slug, root); out[label][slug] = m
        print(f"{slug:<32}{label:>9}{m['f1']:>7.3f}{m['f2_score']:>7.1f}{m['precision']:>7.3f}{m['recall']:>7.3f}{m['TP']:>7}{m['FP']:>7}{m['FN']:>7}")
dst = os.path.join(os.path.dirname(__file__), "..", "reports/evaluation-metrics/realvuln-baselines.json")
json.dump(out, open(dst, "w"), indent=2); print(f"\nsaved {os.path.normpath(dst)}")
