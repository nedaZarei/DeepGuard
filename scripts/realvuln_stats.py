#!/usr/bin/env python3
"""
Statistics for RealVuln comparisons: intervals and paired tests between runs.

For each scanner slug: per-repo TP/FP/FN from the official scorer, micro
precision/recall with Wilson 95% intervals, and a repo-level bootstrap 95%
interval for micro-F1 (resample repos with replacement; captures how much the
number depends on which repos are in the set, which is the dominant source of
uncertainty with a handful of repos).

For a pair of slugs: paired comparison on the same repos only. Reports the
per-repo F1 difference, a sign test, and a paired permutation test on the
micro-F1 difference (sign-flip of per-repo contributions, 10,000 permutations).

Usage:
  RV=~/Documents/university/Real-Vuln-Benchmark python3 scripts/realvuln_stats.py \\
      --slugs deepguard-qwen7b zeroshot-qwen7b deepguard-qwen7b-judge [--gt in_scope|full] \\
      [--pairs deepguard-qwen7b:zeroshot-qwen7b deepguard-qwen7b:deepguard-qwen7b-judge]
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import random
import sys

RV = os.environ.get("RV") or sys.exit("set RV to the Real-Vuln-Benchmark checkout")
sys.path.insert(0, RV)
from parsers import get_parser  # noqa: E402
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402
from scorer.metrics import compute_scorecard  # noqa: E402

FAM = json.load(open(f"{RV}/config/cwe-families.json"))



def _refuse_incomplete(slugs, root):
    bad = [s for s in slugs if os.path.exists(os.path.join(root, "reports", "realvuln-judge", s, "INCOMPLETE"))]
    if bad:
        sys.exit(f"REFUSING to score partial judge/verifier runs (failed model calls): {bad}. "
                 "Re-run them, or delete the INCOMPLETE marker if you really mean it.")

def wilson(k: float, n: float, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def per_repo(slug: str, gt_dir: str, inscope: set | None, unit: str = "repo") -> dict[str, tuple[float, float, float]]:
    """TP/FP/FN per repo, or per file ("<repo>/<path>") with --unit file.

    A GT entry can match in its own file or in the files of its acceptable_locations,
    so those files form one unit; scoring each unit alone then sums exactly to the
    repo totals.
    """
    out, runs = {}, {}
    for res in sorted(glob.glob(f"{RV}/scan-results/realvuln-*/{slug}/*.json")):
        if res.endswith(".metrics.json"):
            continue
        repo = res.split("/")[-3]
        runs[repo] = runs.get(repo, 0) + 1
        gt = load_ground_truth(f"{RV}/{gt_dir}/{repo}/ground-truth.json")
        fs = get_parser(slug).parse(res)
        if inscope is not None:
            fs = [x for x in fs if x.cwe in inscope]
        if unit == "repo":
            parts = {repo: (fs, gt)}
        else:
            unit_of = {}
            for e in gt["findings"]:
                linked = {e["file"]} | {loc["file"] for loc in e.get("acceptable_locations") or [] if loc.get("file")}
                merged = {unit_of.get(g, g) for g in linked}
                key = min(merged)
                for f, u in list(unit_of.items()):
                    if u in merged:
                        unit_of[f] = key
                for g in linked:
                    unit_of[g] = key
            units = {unit_of.get(x.file, x.file) for x in fs} | {unit_of.get(e["file"], e["file"]) for e in gt["findings"]}
            parts = {f"{repo}/{u}": ([x for x in fs if unit_of.get(x.file, x.file) == u],
                                     dict(gt, findings=[e for e in gt["findings"] if unit_of.get(e["file"], e["file"]) == u]))
                     for u in units}
        for key, (pfs, pgt) in parts.items():
            c = compute_scorecard(repo, slug, "", match_findings(pfs, pgt), FAM)
            tp, fp, fn = out.get(key, (0, 0, 0))
            out[key] = (tp + c.tp, fp + c.fp, fn + c.fn)
    # mean over runs for multi-run baselines
    return {key: tuple(v / runs[key.split("/", 1)[0]] for v in vals) for key, vals in out.items()}


def micro(rows: dict, repos) -> tuple[float, float, float, float, float, float]:
    tp = sum(rows.get(r, (0, 0, 0))[0] for r in repos); fp = sum(rows.get(r, (0, 0, 0))[1] for r in repos)
    fn = sum(rows.get(r, (0, 0, 0))[2] for r in repos)
    return (tp, fp, fn) + prf(tp, fp, fn)


def bootstrap_f1(rows: dict, repos: list, n: int = 10000, seed: int = 7) -> tuple[float, float]:
    rng = random.Random(seed)
    vals = []
    for _ in range(n):
        sample = [repos[rng.randrange(len(repos))] for _ in repos]
        vals.append(micro(rows, sample)[5])
    vals.sort()
    return vals[int(0.025 * n)], vals[int(0.975 * n)]


def paired_permutation(rows_a: dict, rows_b: dict, repos: list, n: int = 10000, seed: int = 7) -> float:
    """Two-sided p-value for micro-F1(A) - micro-F1(B) under per-repo sign flips."""
    rng = random.Random(seed)
    observed = micro(rows_a, repos)[5] - micro(rows_b, repos)[5]
    count = 0
    for _ in range(n):
        a, b = {}, {}
        for r in repos:
            ra, rb = rows_a.get(r, (0, 0, 0)), rows_b.get(r, (0, 0, 0))
            a[r], b[r] = (ra, rb) if rng.random() < 0.5 else (rb, ra)
        d = micro(a, repos)[5] - micro(b, repos)[5]
        if abs(d) >= abs(observed) - 1e-12:
            count += 1
    return count / n


def sign_test(diffs: list[float]) -> float:
    pos = sum(1 for d in diffs if d > 0); neg = sum(1 for d in diffs if d < 0)
    n = pos + neg
    if n == 0:
        return 1.0
    k = min(pos, neg)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slugs", nargs="+", required=True)
    ap.add_argument("--pairs", nargs="*", default=[], help="A:B pairs to compare on shared repos")
    ap.add_argument("--gt", choices=["in_scope", "full"], default="in_scope")
    ap.add_argument("--repos", nargs="*", default=None, help="restrict to these repos")
    ap.add_argument("--unit", choices=["repo", "file"], default="repo",
                    help="resampling unit for the bootstrap and the paired tests; file suits a handful of repos")
    args = ap.parse_args()

    gt_dir = "ground-truth-inscope" if args.gt == "in_scope" else "ground-truth"
    inscope = set(json.load(open(f"{RV}/{gt_dir}/in-scope-cwes.json"))) if args.gt == "in_scope" else None

    _refuse_incomplete(args.slugs, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    rows = {s: per_repo(s, gt_dir, inscope, args.unit) for s in args.slugs}
    out = {"gt": args.gt, "unit": args.unit, "scanners": {}, "pairs": {}}

    def repo_of(key):
        return key.split("/", 1)[0]

    print(f"gt={args.gt} unit={args.unit}\n")
    print(f"{'scanner':<32}{args.unit + 's':>6}{'TP':>7}{'FP':>7}{'FN':>7}{'Prec':>7} {'95% CI':<15}{'Rec':>7} {'95% CI':<15}{'F1':>7} {'boot 95% CI':<15}")
    for s in args.slugs:
        repos = sorted(rows[s]) if args.repos is None else [k for r in args.repos for k in sorted(rows[s]) if repo_of(k) == r]
        if not repos:
            print(f"{s:<32} (no results)"); continue
        tp, fp, fn, p, r, f = micro(rows[s], repos)
        pl, ph = wilson(tp, tp + fp); rl, rh = wilson(tp, tp + fn)
        bl, bh = bootstrap_f1(rows[s], repos)
        print(f"{s:<32}{len(repos):>6}{tp:>7.1f}{fp:>7.1f}{fn:>7.1f}{p:>7.3f} [{pl:.3f},{ph:.3f}]{r:>7.3f} [{rl:.3f},{rh:.3f}]{f:>7.3f} [{bl:.3f},{bh:.3f}]")
        out["scanners"][s] = {"repos": repos, "TP": tp, "FP": fp, "FN": fn, "precision": p, "precision_ci": [pl, ph],
                              "recall": r, "recall_ci": [rl, rh], "f1": f, "f1_bootstrap_ci": [bl, bh]}

    for pair in args.pairs:
        a, b = pair.split(":")
        both = {repo_of(k) for k in rows[a]} & {repo_of(k) for k in rows[b]}
        shared = sorted(k for k in set(rows[a]) | set(rows[b]) if repo_of(k) in both)
        if args.repos:
            shared = [r for r in shared if repo_of(r) in args.repos]
        if not shared:
            print(f"\n{a} vs {b}: no shared repos"); continue
        fa = micro(rows[a], shared)[5]; fb = micro(rows[b], shared)[5]
        diffs = [prf(*rows[a].get(r, (0, 0, 0)))[2] - prf(*rows[b].get(r, (0, 0, 0)))[2] for r in shared]
        pperm = paired_permutation(rows[a], rows[b], shared)
        psign = sign_test(diffs)
        wins = sum(1 for d in diffs if d > 0)
        print(f"\n{a} vs {b} on {len(shared)} shared {args.unit}s:")
        print(f"  micro-F1 {fa:.3f} vs {fb:.3f}  (diff {fa - fb:+.3f}); per-{args.unit} F1: {a} better on {wins}/{len(shared)}")
        print(f"  paired permutation p={pperm:.4f}   sign test p={psign:.4f}")
        out["pairs"][pair] = {"repos": shared, "f1_a": fa, "f1_b": fb, "diff": fa - fb, "per_repo_diffs": dict(zip(shared, diffs)),
                              "wins_a": wins, "perm_p": pperm, "sign_p": psign}

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    suffix = "" if args.unit == "repo" else f"-{args.unit}"
    dst = os.path.join(root, "reports", "evaluation-metrics", f"realvuln-stats-{args.gt}{suffix}.json")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    json.dump(out, open(dst, "w"), indent=2)
    print(f"\nsaved {os.path.relpath(dst, root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
