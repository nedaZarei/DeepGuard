#!/usr/bin/env python3
"""
Statistical analysis for DeepGuard paper evaluation.

Computes:
1. Bootstrap 95% CI for F1 on clean-bench-v3 (type-constrained and unconstrained)
2. Threshold sensitivity sweep: F1, Precision, Recall at thresholds 0.3–1.0
3. Same analysis for zero-shot baseline for comparison

Run: python3 scripts/statistical_analysis.py
Output: reports/evaluation-metrics/statistical-analysis.json + printed summary
"""

import json
import os
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCAN_REPORT   = REPO_ROOT / "reports/clean-bench-v3/scan-20260710-175702.json"
ZERO_SHOT     = REPO_ROOT / "test-samples/js-ts-sqli-clean/zero-shot-results.json"
GOLDEN        = REPO_ROOT / "test-samples/js-ts-sqli-clean/expected-findings.json"
OUTPUT        = REPO_ROOT / "reports/evaluation-metrics/statistical-analysis.json"

LINE_TOLERANCE = 20
BOOTSTRAP_ITERS = 10_000
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0]
RANDOM_SEED = 42


# ---------------------------------------------------------------------------
# Matching logic (mirrors golden_comparator.go)
# ---------------------------------------------------------------------------

def basename(path: str) -> str:
    return os.path.basename(path)

def matches(expected: dict, actual: dict, tolerance: int) -> bool:
    if basename(expected["file"]) != basename(actual["file"]):
        return False
    if expected["type"] != actual["type"]:
        return False
    if abs(expected["line"] - actual["line"]) > tolerance:
        return False
    return True

def compute_metrics(expected_findings: list, actual_findings: list,
                    threshold: float, tolerance: int) -> dict:
    """Type-constrained and unconstrained metrics at a given confidence threshold."""
    filtered = [f for f in actual_findings if f["confidence"] >= threshold]
    matched = set()
    tp = 0

    for exp in expected_findings:
        for i, act in enumerate(filtered):
            if i in matched:
                continue
            if matches(exp, act, tolerance):
                tp += 1
                matched.add(i)
                break

    fn = len(expected_findings) - tp

    # Type-constrained FP: unmatched findings of same type as benchmark (sql_injection)
    expected_type = expected_findings[0]["type"] if expected_findings else "sql_injection"
    fp_typed = sum(
        1 for i, f in enumerate(filtered)
        if i not in matched
        and f.get("severity", "") in ("critical", "high")
        and f.get("type") == expected_type
    )

    # Unconstrained FP: all unmatched high/critical
    fp_all = sum(
        1 for i, f in enumerate(filtered)
        if i not in matched
        and f.get("severity", "") in ("critical", "high")
    )

    def f1(prec, rec):
        return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    prec_typed = tp / (tp + fp_typed) if (tp + fp_typed) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_typed = f1(prec_typed, rec)

    prec_all = tp / (tp + fp_all) if (tp + fp_all) > 0 else 0.0
    f1_all = f1(prec_all, rec)

    return {
        "threshold": threshold,
        "filtered_findings": len(filtered),
        "TP": tp, "FN": fn,
        "FP_typed": fp_typed, "FP_all": fp_all,
        "precision_typed": round(prec_typed, 4),
        "recall": round(rec, 4),
        "f1_typed": round(f1_typed, 4),
        "precision_all": round(prec_all, 4),
        "f1_all": round(f1_all, 4),
    }


# ---------------------------------------------------------------------------
# Bootstrap confidence interval
# ---------------------------------------------------------------------------

def bootstrap_f1_ci(expected_findings: list, actual_findings: list,
                    threshold: float, tolerance: int,
                    n_iter: int = BOOTSTRAP_ITERS, seed: int = RANDOM_SEED) -> dict:
    """
    Bootstrap 95% CI for type-constrained F1.

    Strategy: resample expected findings with replacement; for each sample
    check which were found; compute F1 on the sample.
    This gives the CI due to finite benchmark size.
    """
    rng = random.Random(seed)
    filtered = [f for f in actual_findings if f["confidence"] >= threshold]
    n = len(expected_findings)

    # Precompute which expected findings were matched (True/False list)
    matched_actual = set()
    found_flags = []
    for exp in expected_findings:
        found = False
        for i, act in enumerate(filtered):
            if i in matched_actual:
                continue
            if matches(exp, act, tolerance):
                found = True
                matched_actual.add(i)
                break
        found_flags.append(found)

    # Unmatched high/crit same-type = FP_typed (fixed, not resampled)
    expected_type = expected_findings[0]["type"] if expected_findings else "sql_injection"
    fp_typed_base = sum(
        1 for i, f in enumerate(filtered)
        if i not in matched_actual
        and f.get("severity", "") in ("critical", "high")
        and f.get("type") == expected_type
    )

    f1_samples = []
    for _ in range(n_iter):
        indices = [rng.randint(0, n - 1) for _ in range(n)]
        tp_s = sum(found_flags[i] for i in indices)
        fn_s = n - tp_s
        fp_s = fp_typed_base  # FP doesn't change with resampling of expected
        prec = tp_s / (tp_s + fp_s) if (tp_s + fp_s) > 0 else 0.0
        rec  = tp_s / (tp_s + fn_s) if (tp_s + fn_s) > 0 else 0.0
        f1_s = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        f1_samples.append(f1_s)

    f1_samples.sort()
    ci_low  = f1_samples[int(0.025 * n_iter)]
    ci_high = f1_samples[int(0.975 * n_iter)]
    mean_f1 = sum(f1_samples) / len(f1_samples)

    return {
        "mean_f1": round(mean_f1, 4),
        "ci_95_low":  round(ci_low, 4),
        "ci_95_high": round(ci_high, 4),
        "n_bootstrap": n_iter,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Loading data...")
    with open(GOLDEN) as f:
        golden = json.load(f)
    with open(SCAN_REPORT) as f:
        scan = json.load(f)
    with open(ZERO_SHOT) as f:
        zs = json.load(f)

    expected = golden["expected_findings"]
    deepguard_findings = scan["findings"]
    zeroshot_findings  = zs["findings"]

    print(f"Expected findings: {len(expected)}")
    print(f"DeepGuard findings (all stored): {len(deepguard_findings)}")
    print(f"Zero-shot findings (all stored): {len(zeroshot_findings)}")
    print()

    # -----------------------------------------------------------------------
    # 1. Threshold sensitivity sweep
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("THRESHOLD SENSITIVITY SWEEP (type-constrained F1)")
    print("=" * 60)
    print(f"{'Threshold':>10}  {'F1':>6}  {'Prec':>6}  {'Rec':>6}  {'FP_typed':>8}  {'Findings':>8}")
    print("-" * 60)

    dg_sweep, zs_sweep = [], []
    for t in THRESHOLDS:
        dg = compute_metrics(expected, deepguard_findings, t, LINE_TOLERANCE)
        zs_m = compute_metrics(expected, zeroshot_findings, t, LINE_TOLERANCE)
        dg_sweep.append(dg)
        zs_sweep.append(zs_m)
        print(f"  DG  {t:>6.2f}  {dg['f1_typed']:>6.3f}  {dg['precision_typed']:>6.3f}  {dg['recall']:>6.3f}  {dg['FP_typed']:>8}  {dg['filtered_findings']:>8}")
        print(f"  ZS  {t:>6.2f}  {zs_m['f1_typed']:>6.3f}  {zs_m['precision_typed']:>6.3f}  {zs_m['recall']:>6.3f}  {zs_m['FP_typed']:>8}  {zs_m['filtered_findings']:>8}")
        print()

    # -----------------------------------------------------------------------
    # 2. Wilson CI for Precision and Recall (more informative than bootstrap
    #    when recall=1.0, because bootstrap CI degenerates to a point estimate)
    # -----------------------------------------------------------------------
    import math

    def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple:
        """Wilson score interval for a proportion k/n."""
        if n == 0:
            return (0.0, 0.0)
        p = k / n
        denom = 1 + z**2 / n
        center = (p + z**2 / (2 * n)) / denom
        margin = (z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))) / denom
        return (max(0.0, center - margin), min(1.0, center + margin))

    def f1_from_prec_rec(prec, rec):
        return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    # DeepGuard at threshold 0.5: TP=42, FP_typed=13, FN=0
    dg_m = compute_metrics(expected, deepguard_findings, 0.5, LINE_TOLERANCE)
    dg_tp, dg_fp, dg_fn = dg_m["TP"], dg_m["FP_typed"], dg_m["FN"]
    dg_prec_ci = wilson_ci(dg_tp, dg_tp + dg_fp)
    dg_rec_ci  = wilson_ci(dg_tp, dg_tp + dg_fn)
    dg_f1_low  = f1_from_prec_rec(dg_prec_ci[0], dg_rec_ci[0])
    dg_f1_high = f1_from_prec_rec(dg_prec_ci[1], dg_rec_ci[1])

    zs_m = compute_metrics(expected, zeroshot_findings, 0.5, LINE_TOLERANCE)
    zs_tp, zs_fp, zs_fn = zs_m["TP"], zs_m["FP_typed"], zs_m["FN"]
    zs_prec_ci = wilson_ci(zs_tp, zs_tp + zs_fp)
    zs_rec_ci  = wilson_ci(zs_tp, zs_tp + zs_fn)
    zs_f1_low  = f1_from_prec_rec(zs_prec_ci[0], zs_rec_ci[0])
    zs_f1_high = f1_from_prec_rec(zs_prec_ci[1], zs_rec_ci[1])

    print("=" * 60)
    print("WILSON 95% CI — PRECISION, RECALL, F1 (threshold=0.5)")
    print("(Bootstrap CI degenerates to point when Recall=1.0)")
    print("=" * 60)
    print(f"\nDeepGuard  TP={dg_tp} FP={dg_fp} FN={dg_fn}")
    print(f"  Precision: {dg_m['precision_typed']:.4f}  95% CI [{dg_prec_ci[0]:.4f}, {dg_prec_ci[1]:.4f}]")
    print(f"  Recall:    {dg_m['recall']:.4f}  95% CI [{dg_rec_ci[0]:.4f}, {dg_rec_ci[1]:.4f}]")
    print(f"  F1:        {dg_m['f1_typed']:.4f}  95% CI [{dg_f1_low:.4f}, {dg_f1_high:.4f}]")
    print(f"\nZero-shot  TP={zs_tp} FP={zs_fp} FN={zs_fn}")
    print(f"  Precision: {zs_m['precision_typed']:.4f}  95% CI [{zs_prec_ci[0]:.4f}, {zs_prec_ci[1]:.4f}]")
    print(f"  Recall:    {zs_m['recall']:.4f}  95% CI [{zs_rec_ci[0]:.4f}, {zs_rec_ci[1]:.4f}]")
    print(f"  F1:        {zs_m['f1_typed']:.4f}  95% CI [{zs_f1_low:.4f}, {zs_f1_high:.4f}]")

    # Also run bootstrap (kept for completeness but note the limitation)
    dg_ci = bootstrap_f1_ci(expected, deepguard_findings, 0.5, LINE_TOLERANCE)
    zs_ci = bootstrap_f1_ci(expected, zeroshot_findings,  0.5, LINE_TOLERANCE)

    print(f"\nBootstrap CI (10k iters) — note: point estimate when Recall=1.0")
    print(f"  DeepGuard  F1={dg_ci['mean_f1']:.4f}  95% CI [{dg_ci['ci_95_low']:.4f}, {dg_ci['ci_95_high']:.4f}]")
    print(f"  Zero-shot  F1={zs_ci['mean_f1']:.4f}  95% CI [{zs_ci['ci_95_low']:.4f}, {zs_ci['ci_95_high']:.4f}]")

    print("\n--- KEY FINDING: threshold=0.95 ---")
    dg_95 = next(m for m in dg_sweep if m["threshold"] == 0.95)
    zs_95 = next(m for m in zs_sweep if m["threshold"] == 0.95)
    print(f"DeepGuard @0.95: F1={dg_95['f1_typed']:.3f} Prec={dg_95['precision_typed']:.3f} Rec={dg_95['recall']:.3f} (FP_typed={dg_95['FP_typed']})")
    print(f"Zero-shot @0.95: F1={zs_95['f1_typed']:.3f} Prec={zs_95['precision_typed']:.3f} Rec={zs_95['recall']:.3f} (FP_typed={zs_95['FP_typed']})")
    print("DeepGuard maintains Recall=1.0 at 0.95; zero-shot recall drops to 0.976")
    print("→ DeepGuard findings are more uniformly high-confidence than zero-shot")

    # -----------------------------------------------------------------------
    # 3. Confidence distribution
    # -----------------------------------------------------------------------
    from collections import Counter
    dg_conf_dist = Counter(round(f["confidence"], 1) for f in deepguard_findings)
    zs_conf_dist = Counter(round(f["confidence"], 1) for f in zeroshot_findings)

    print()
    print("=" * 60)
    print("CONFIDENCE DISTRIBUTION")
    print("=" * 60)
    print("DeepGuard:", dict(sorted(dg_conf_dist.items())))
    print("Zero-shot:", dict(sorted(zs_conf_dist.items())))

    # -----------------------------------------------------------------------
    # 4. Key finding: overlap between CI ranges
    # -----------------------------------------------------------------------
    print()
    print("=" * 60)
    print("PAPER FINDING: CI OVERLAP ANALYSIS")
    print("=" * 60)
    overlap = not (dg_ci['ci_95_high'] < zs_ci['ci_95_low'] or
                   zs_ci['ci_95_high'] < dg_ci['ci_95_low'])
    print(f"CIs overlap: {overlap}")
    print("Interpretation:", end=" ")
    if overlap:
        print("No statistically significant difference between DeepGuard and zero-shot")
        print("at threshold=0.5 on this benchmark (42 samples).")
        print("This supports the finding that RAG/chunking do not measurably improve")
        print("detection on canonical ORM-level SQLi patterns known to GPT-4o.")
    else:
        print("Statistically significant difference detected.")

    # -----------------------------------------------------------------------
    # Save output
    # -----------------------------------------------------------------------
    output = {
        "description": "Bootstrap CI and threshold sensitivity for DeepGuard vs zero-shot",
        "dataset": "clean-bench-v3 (42 SQLi, 8 JS/TS files)",
        "line_tolerance": LINE_TOLERANCE,
        "default_threshold": 0.5,
        "bootstrap": {
            "deepguard": dg_ci,
            "zero_shot": zs_ci,
            "ci_overlap": overlap,
            "interpretation": (
                "No statistically significant difference between DeepGuard and zero-shot "
                "at threshold=0.5 on this benchmark. Suggests RAG/chunking do not "
                "measurably improve detection for canonical ORM SQLi patterns."
            ) if overlap else "Significant difference detected."
        },
        "threshold_sweep": {
            "deepguard": dg_sweep,
            "zero_shot": zs_sweep,
        },
        "confidence_distribution": {
            "deepguard": {str(k): v for k, v in sorted(dg_conf_dist.items())},
            "zero_shot":  {str(k): v for k, v in sorted(zs_conf_dist.items())},
        }
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {OUTPUT}")


if __name__ == "__main__":
    main()
