#!/usr/bin/env python3
"""
False-positive taxonomy for a DeepGuard run on RealVuln (RQ3).

Classifies every scanner finding the official scorer marks FP into one of:
  wrong_type          right file, a real vulnerability within ±10 lines, but the
                      finding's CWE is not in that entry's acceptable list
  line_off_11_30      right file and CWE, real vulnerability 11-30 lines away
  duplicate_site      another finding of the same run already sits on this line
  gt_claimed_or_far   same file+CWE has a real vulnerability, but it was already
                      matched by another finding, or is >30 lines away
  fp_trap             matches a labelled `is_vulnerable: false` decoy
  no_nearby_gt        nothing labelled nearby: a genuine false alarm (or an
                      unlabelled true finding; we cannot tell without review)

Also writes a random sample of FPs (with surrounding source lines) to a CSV
for manual verification of the automatic labels, and prints upper bounds for
what removing each category would do to precision/F1.

Usage:
  RV=~/Documents/university/Real-Vuln-Benchmark python3 scripts/realvuln_fp_taxonomy.py \\
      --slug deepguard-qwen7b [--gt in_scope|full] [--sample 30] [--seed 7]
"""
from __future__ import annotations

import argparse
import collections
import csv
import glob
import json
import os
import random
import sys

RV = os.environ.get("RV") or sys.exit("set RV to the Real-Vuln-Benchmark checkout")
sys.path.insert(0, RV)
from parsers import get_parser  # noqa: E402
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402
from scorer.metrics import compute_scorecard  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAM = json.load(open(f"{RV}/config/cwe-families.json"))
CWE2FAMILY = {}
for fam_name, fam in FAM["families"].items():
    for c in fam["cwes"]:
        CWE2FAMILY.setdefault(c, fam_name)


def repos_for(slug: str) -> list[str]:
    return sorted(p.split("/")[-3] for p in glob.glob(f"{RV}/scan-results/realvuln-*/{slug}/results.json"))


def load_findings(repo: str, slug: str, inscope_cwes: set | None):
    fs = get_parser(slug).parse(f"{RV}/scan-results/{repo}/{slug}/results.json")
    if inscope_cwes is not None:
        fs = [x for x in fs if x.cwe in inscope_cwes]
    return fs


def near(a: int | None, entry: dict, tol: int) -> bool:
    if not a:
        return False
    loc = entry["location"]
    start, end = loc["start_line"], loc.get("end_line", loc["start_line"])
    return start - tol <= a <= end + tol


def classify(x, m, findings, vulns, tp_lines) -> tuple[str, str]:
    """Return (category, note) for one FP finding x with match-result m."""
    if m.ground_truth_entry is not None:
        return "fp_trap", m.ground_truth_entry.get("id", "")
    same_file = [e for e in vulns if e["file"] == x.file]
    wrong_type = [e for e in same_file if x.cwe not in e["acceptable_cwes"] and near(x.line, e, 10)]
    if wrong_type:
        e = wrong_type[0]
        return "wrong_type", f"said {CWE2FAMILY.get(x.cwe, x.cwe)}, GT {e['vulnerability_class']} @{e['location']['start_line']}"
    same_cwe = [e for e in same_file if x.cwe in e["acceptable_cwes"]]
    off = [e for e in same_cwe if near(x.line, e, 30) and not near(x.line, e, 10)]
    if off:
        e = off[0]
        return "line_off_11_30", f"GT @{e['location']['start_line']}, reported {x.line}"
    if (x.file, x.line) in tp_lines or sum(1 for y in findings if y.file == x.file and y.line == x.line) > 1:
        return "duplicate_site", ""
    if same_cwe:
        return "gt_claimed_or_far", f"nearest GT @{min(same_cwe, key=lambda e: abs((e['location']['start_line'] or 0) - (x.line or 0)))['location']['start_line']}"
    return "no_nearby_gt", ""


def source_context(repo: str, file: str, line: int | None, width: int = 2) -> str:
    path = os.path.join(RV, "repos", repo, file)
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return "<file not found>"
    if not line:
        return ""
    lo, hi = max(1, line - width), min(len(lines), line + width)
    return "\n".join(f"{i}{'>' if i == line else ' '} {lines[i - 1]}" for i in range(lo, hi + 1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True)
    ap.add_argument("--gt", choices=["in_scope", "full"], default="in_scope")
    ap.add_argument("--sample", type=int, default=30, help="FPs to write out for manual review")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    gt_dir = "ground-truth-inscope" if args.gt == "in_scope" else "ground-truth"
    inscope = None
    if args.gt == "in_scope":
        inscope = set(json.load(open(f"{RV}/{gt_dir}/in-scope-cwes.json")))

    repos = repos_for(args.slug)
    if not repos:
        sys.exit(f"no results for slug {args.slug}")

    cats = collections.Counter()
    pairs = collections.Counter()
    rows = []
    tp = fp = fn = 0
    for repo in repos:
        gt = load_ground_truth(f"{RV}/{gt_dir}/{repo}/ground-truth.json")
        vulns = [e for e in gt["findings"] if e["is_vulnerable"]]
        fs = load_findings(repo, args.slug, inscope)
        ms = match_findings(fs, gt)
        card = compute_scorecard(repo, args.slug, "", ms, FAM)
        tp += card.tp; fp += card.fp; fn += card.fn
        tp_lines = {(m.scanner_finding.file, m.scanner_finding.line) for m in ms if m.classification == "TP"}
        for m in ms:
            if m.classification != "FP":
                continue
            x = m.scanner_finding
            cat, note = classify(x, m, fs, vulns, tp_lines)
            cats[cat] += 1
            if cat == "wrong_type":
                pairs[note.split(" @")[0]] += 1
            rows.append({"repo": repo, "file": x.file, "line": x.line, "cwe": x.cwe,
                         "type": CWE2FAMILY.get(x.cwe, x.cwe), "category": cat, "note": note,
                         "message": (x.message or "")[:120],
                         "context": source_context(repo, x.file, x.line)})

    total_fp = sum(cats.values())
    print(f"slug={args.slug} gt={args.gt} repos={len(repos)}  TP={tp} FP={fp} FN={fn}")
    print("\nFP taxonomy:")
    for k, v in cats.most_common():
        print(f"  {v:>5}  {v / total_fp:5.1%}  {k}")
    print("\nMost common wrong-type pairs:")
    for k, v in pairs.most_common(8):
        print(f"  {v:>5}  {k}")

    # Upper bounds: remove a category outright (recall unchanged, so this is optimistic)
    rec = tp / (tp + fn) if tp + fn else 0
    print("\nUpper bounds if a category were fully removed (recall held):")
    cum = 0
    for k, v in cats.most_common():
        cum += v
        p = tp / (tp + fp - cum) if tp + fp - cum else 0
        f1 = 2 * p * rec / (p + rec) if p + rec else 0
        print(f"  -{k:<20} cumulative  Prec={p:.3f}  F1={f1:.3f}")

    out_dir = os.path.join(ROOT, "reports", "evaluation-metrics")
    os.makedirs(out_dir, exist_ok=True)
    summary = {"slug": args.slug, "gt": args.gt, "repos": repos, "TP": tp, "FP": fp, "FN": fn,
               "taxonomy": dict(cats), "wrong_type_pairs": dict(pairs.most_common(20))}
    with open(os.path.join(out_dir, f"realvuln-fp-taxonomy-{args.slug}.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    random.seed(args.seed)
    sample = random.sample(rows, min(args.sample, len(rows)))
    sample_path = os.path.join(out_dir, f"realvuln-fp-sample-{args.slug}.csv")
    with open(sample_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["repo", "file", "line", "cwe", "type", "category", "note",
                                           "message", "context", "human_verdict", "human_note"])
        w.writeheader()
        for r in sample:
            w.writerow({**r, "human_verdict": "", "human_note": ""})
    print(f"\nsaved summary and a {len(sample)}-row review sample under reports/evaluation-metrics/")
    print("fill human_verdict with one of: agree | true_finding_unlabelled | other")
    return 0


if __name__ == "__main__":
    sys.exit(main())
