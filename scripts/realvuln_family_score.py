#!/usr/bin/env python3
"""
Family-level scoring for DeepGuard runs on RealVuln (secondary metric).

The official scorer matches a finding only if its single CWE is in the ground-truth
entry's acceptable list, and the Semgrep parser turns a multi-CWE finding into several
findings (each unmatched one a false positive). DeepGuard reports a vulnerability *type*,
not a CWE, and our adapter therefore emits one representative CWE per type. Some RealVuln
entries accept only a sibling CWE (BOLA: CWE-639; missing authorization: CWE-862;
predictable token: CWE-330; code injection: CWE-94/95), so a correct DeepGuard finding at
the right line can be unmatchable by construction.

This script re-scores with the same file and +-10-line rules but lets ONE finding match
if ANY CWE in its type's family intersects the entry's acceptable_cwes. One finding still
claims at most one entry; unmatched findings are FP; FP traps still count. It is reported
alongside, never instead of, the official numbers.

Usage:
  RV=... python3 scripts/realvuln_family_score.py --slugs deepguard-qwen7b-js semgrep [--gt in_scope|full] [--repos ...]
"""
from __future__ import annotations
import argparse, glob, json, os, sys

RV = os.environ.get("RV") or sys.exit("set RV")
sys.path.insert(0, RV)
from parsers import get_parser  # noqa: E402

# DeepGuard type -> CWE family (superset of the adapter's single CWE).
TYPE_FAMILY = {
    "sql_injection":            {"CWE-89", "CWE-564", "CWE-943"},
    "xss":                      {"CWE-79", "CWE-80", "CWE-87", "CWE-116"},
    "command_injection":        {"CWE-78", "CWE-77", "CWE-94", "CWE-95"},
    "ssrf":                     {"CWE-918", "CWE-441"},
    "path_traversal":           {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-434"},
    "insecure_deserialization": {"CWE-502"},
    "xxe":                      {"CWE-611", "CWE-827", "CWE-776"},
    "auth_issue":               {"CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-639", "CWE-306", "CWE-287", "CWE-613", "CWE-384", "CWE-347"},
    "crypto_issue":             {"CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-916", "CWE-256", "CWE-312"},
}
CWE_TO_TYPE = {c: t for t, cs in TYPE_FAMILY.items() for c in cs}



def _refuse_incomplete(slugs, root):
    bad = [s for s in slugs if os.path.exists(os.path.join(root, "reports", "realvuln-judge", s, "INCOMPLETE"))]
    if bad:
        sys.exit(f"REFUSING to score partial judge/verifier runs (failed model calls): {bad}. "
                 "Re-run them, or delete the INCOMPLETE marker if you really mean it.")

def family_of(cwe: str) -> set:
    return TYPE_FAMILY.get(CWE_TO_TYPE.get(cwe, ""), {cwe})


def score_repo(findings, gt: dict):
    entries = [e for e in gt["findings"]]
    claimed = set(); tp = fp = 0
    for f in findings:
        cands = []
        for i, e in enumerate(entries):
            if i in claimed or e["file"] != f.file:
                continue
            s = e["location"]["start_line"]; ee = e["location"].get("end_line", s)
            if f.line is None or not (s - 10 <= f.line <= ee + 10):
                continue
            if family_of(f.cwe) & set(e["acceptable_cwes"]):
                cands.append(i)
        if cands:
            cands.sort(key=lambda i: not entries[i]["is_vulnerable"])
            i = cands[0]; claimed.add(i)
            if entries[i]["is_vulnerable"]: tp += 1
            else: fp += 1
        else:
            fp += 1
    fn = sum(1 for i, e in enumerate(entries) if e["is_vulnerable"] and i not in claimed)
    return tp, fp, fn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slugs", nargs="+", required=True)
    ap.add_argument("--gt", choices=["in_scope", "full"], default="in_scope")
    ap.add_argument("--repos", nargs="*", default=None)
    a = ap.parse_args()
    gt_dir = "ground-truth-inscope" if a.gt == "in_scope" else "ground-truth"
    inscope = set(json.load(open(f"{RV}/{gt_dir}/in-scope-cwes.json"))) if a.gt == "in_scope" else None
    print(f"family-level scoring, gt={a.gt}\n{'scanner':<34}{'repos':>6}{'TP':>6}{'FP':>6}{'FN':>6}{'Prec':>7}{'Rec':>7}{'F1':>7}")
    _refuse_incomplete(a.slugs, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out = {}
    for slug in a.slugs:
        files = sorted(glob.glob(f"{RV}/scan-results/realvuln-*/{slug}/results.json"))
        tp = fp = fn = 0; n = 0
        for res in files:
            repo = res.split("/")[-3]
            if a.repos and repo not in a.repos: continue
            gt = json.load(open(f"{RV}/{gt_dir}/{repo}/ground-truth.json"))
            for e in gt["findings"]:
                e["file"] = e["file"].lstrip("./")
            fs = get_parser(slug).parse(res)
            if inscope is not None:
                fs = [x for x in fs if x.cwe in inscope or CWE_TO_TYPE.get(x.cwe)]
            t, f_, n_ = score_repo(fs, gt); tp += t; fp += f_; fn += n_; n += 1
        p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0; f1 = 2 * p * r / (p + r) if p + r else 0
        print(f"{slug:<34}{n:>6}{tp:>6}{fp:>6}{fn:>6}{p:>7.3f}{r:>7.3f}{f1:>7.3f}")
        out[slug] = dict(repos=n, TP=tp, FP=fp, FN=fn, precision=p, recall=r, f1=f1)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json.dump(out, open(os.path.join(root, "reports/evaluation-metrics", f"realvuln-family-{a.gt}.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
