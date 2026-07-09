#!/usr/bin/env python3
"""
Multi-type, multi-language evaluation: Deep-Guard vs Bandit.

Dataset: test-samples/python-multi-vuln/
  29 labeled findings, 4 files, 10 vulnerability types
  Designed to expose pattern-matching blind spots:
    - SSRF:          0 Bandit rules
    - XSS (dynamic): 0 Bandit rules (f-string/concat into render_template_string)
    - JWT issues:    0 Bandit rules
    - Path traversal via os.path.join: 0 Bandit rules
    - Zip slip:      0 Bandit rules

Usage:
  # Bandit only (no API key needed — Bandit runs automatically):
  python3 scripts/multi_type_evaluation.py

  # Include Deep-Guard results (run the scan first):
  DEEPGUARD_OPENAI_API_KEY=<key> ./deepguard scan \\
      --path test-samples/python-multi-vuln \\
      --output test-samples/python-multi-vuln \\
      --confidence-threshold 0.5
  # Then rename: mv test-samples/python-multi-vuln/deep-guard-*.json \\
  #               test-samples/python-multi-vuln/deep-guard-results.json
  python3 scripts/multi_type_evaluation.py
"""

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT   = Path(__file__).parent.parent
BENCH_DIR   = REPO_ROOT / "test-samples/python-multi-vuln"
GOLDEN_PATH = BENCH_DIR / "expected-findings.json"
DG_PATH     = Path(os.environ.get(
    "DEEPGUARD_SCAN", str(BENCH_DIR / "deep-guard-results.json")))

LINE_TOL_BANDIT  = 5    # tight: Bandit is deterministic
LINE_TOL_DG      = 20   # wider: LLM line attribution varies ±20
LINE_TOL_DG_WIDE = 60   # for type-agnostic detection check (line offset bug workaround)


def load_json(p):
    with open(p) as f:
        return json.load(f)


def normalize(path):
    return os.path.basename(str(path))


# ── Bandit ───────────────────────────────────────────────────────────────────

def run_bandit():
    r = subprocess.run(
        ["bandit", "-r", str(BENCH_DIR), "-f", "json"],
        capture_output=True, text=True
    )
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return []

    sev_map = {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}
    return [
        {
            "file": res["filename"],
            "line": res["line_number"],
            "type": None,           # type-agnostic matching for Bandit
            "severity": sev_map.get(res["issue_severity"].upper(), "low"),
            "confidence": 1.0,
            "message": res["issue_text"],
            "rule": res["test_id"],
        }
        for res in data.get("results", [])
    ]


# ── Matching ─────────────────────────────────────────────────────────────────

def match(expected_list, actual_list, tolerance, require_type=True):
    """Match expected findings to actual; return TP, FP list, FN list."""
    matched = set()
    tp, missing = 0, []

    for exp in expected_list:
        exp_file = normalize(exp["file"])
        found = False
        for i, act in enumerate(actual_list):
            if i in matched:
                continue
            if normalize(act["file"]) != exp_file:
                continue
            if require_type and act.get("type") and exp.get("type") and act["type"] != exp["type"]:
                continue
            if abs(act["line"] - exp["line"]) > tolerance:
                continue
            matched.add(i)
            tp += 1
            found = True
            break
        if not found:
            missing.append(exp)

    fp_list = [act for i, act in enumerate(actual_list) if i not in matched]
    return tp, fp_list, missing


def metrics(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def by_type_breakdown(tp_matched_pairs, missing, fp_list, expected_list):
    """Return per-type TP/FN/FP counts."""
    type_tp = defaultdict(int)
    type_fn = defaultdict(int)
    type_fp = defaultdict(int)

    # We don't have pair info here; derive from missing and totals
    all_types = {e["type"] for e in expected_list}
    type_total = defaultdict(int)
    for e in expected_list:
        type_total[e["type"]] += 1

    for m in missing:
        type_fn[m["type"]] += 1

    for t in all_types:
        type_tp[t] = type_total[t] - type_fn[t]

    for fp in fp_list:
        t = fp.get("type") or "unknown"
        type_fp[t] += 1

    return all_types, type_total, type_tp, type_fn, type_fp


def hdr(text, width=70):
    print(f"\n─── {text} {'─' * max(0, width - len(text) - 5)}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if not GOLDEN_PATH.exists():
        print(f"ERROR: {GOLDEN_PATH} not found", file=sys.stderr)
        sys.exit(1)

    golden   = load_json(GOLDEN_PATH)
    expected = golden["expected_findings"]
    n_types  = len(set(e["type"] for e in expected))

    print("=" * 70)
    print("DEEP-GUARD vs BANDIT — MULTI-TYPE PYTHON EVALUATION")
    print("=" * 70)
    print(f"\nBenchmark  : {BENCH_DIR.relative_to(REPO_ROOT)}")
    print(f"Findings   : {len(expected)} labeled findings across 4 files")
    print(f"Types      : {n_types} vulnerability categories")
    print(f"             {', '.join(sorted(set(e['type'] for e in expected)))}")

    # ── BANDIT ───────────────────────────────────────────────────────────────
    hdr("Bandit 1.8.6  (automatic)")
    bandit_findings = run_bandit()
    print(f"  Raw output: {len(bandit_findings)} findings")

    b_tp, b_fp_list, b_missing = match(expected, bandit_findings, LINE_TOL_BANDIT)
    b_fp = len(b_fp_list)
    b_fn = len(b_missing)
    b_p, b_r, b_f = metrics(b_tp, b_fp, b_fn)

    print(f"  TP={b_tp}  FP={b_fp}  FN={b_fn}")
    print(f"  Precision={b_p:.3f}  Recall={b_r:.3f}  F1={b_f:.3f}")

    # Per-type breakdown for Bandit
    all_types, type_total, btype_tp, btype_fn, btype_fp = by_type_breakdown(
        [], b_missing, b_fp_list, expected)

    print(f"\n  Per-type recall:")
    for t in sorted(all_types):
        tp_t = type_total[t] - btype_fn[t]
        rec_t = tp_t / type_total[t] if type_total[t] else 0
        flag = "✅" if rec_t >= 0.5 else "❌"
        print(f"    {flag}  {t:<28}  {tp_t}/{type_total[t]}  ({rec_t:.0%})")

    if b_missing:
        print(f"\n  Missed findings ({b_fn}):")
        for m in b_missing:
            print(f"    {normalize(m['file'])}:{m['line']:3d}  [{m['type']}]  {m['description'][:55]}")
            print(f"           → {m['bandit_rule']}")

    # ── DEEP-GUARD ───────────────────────────────────────────────────────────
    hdr("Deep-Guard")
    if not DG_PATH.exists():
        print(f"  No results at {DG_PATH.relative_to(REPO_ROOT)}")
        print(f"\n  To run:")
        print(f"    export DEEPGUARD_OPENAI_API_KEY=<your-key>")
        print(f"    ./deepguard scan --path {BENCH_DIR.relative_to(REPO_ROOT)} \\")
        print(f"        --output {BENCH_DIR.relative_to(REPO_ROOT)} --confidence-threshold 0.5")
        print(f"    mv {BENCH_DIR.relative_to(REPO_ROOT)}/deep-guard-*.json \\")
        print(f"       {BENCH_DIR.relative_to(REPO_ROOT)}/deep-guard-results.json")
        dg_available = False
    else:
        dg_data = load_json(DG_PATH)
        dg_raw  = dg_data.get("findings", [])
        dg_cost = dg_data.get("scan_metadata", {}).get("total_cost", 0)

        # Only count high/critical for FP (matches golden_comparator logic)
        HIGH_SEVER = {"critical", "high"}
        dg_findings = [
            {"file": f["file"], "line": f["line"], "type": f["type"],
             "severity": f["severity"], "confidence": f.get("confidence", 0),
             "message": f.get("message", "")}
            for f in dg_raw if f.get("severity") in HIGH_SEVER
        ]
        print(f"  Scan cost: ${dg_cost:.4f}")
        print(f"  High/Critical findings: {len(dg_findings)}")
        for f in dg_findings:
            print(f"  {normalize(f['file'])}:{f['line']:3d}  [{f['type']}/{f['severity']}  conf={f['confidence']:.2f}]  {f['message'][:50]}")

        dg_tp, dg_fp_list, dg_missing = match(expected, dg_findings, LINE_TOL_DG)
        dg_fp = len(dg_fp_list)
        dg_fn = len(dg_missing)
        dg_p, dg_r, dg_f = metrics(dg_tp, dg_fp, dg_fn)

        print(f"\n  TP={dg_tp}  FP={dg_fp}  FN={dg_fn}")
        print(f"  Precision={dg_p:.3f}  Recall={dg_r:.3f}  F1={dg_f:.3f}")

        _, _, dgtype_tp, dgtype_fn, dgtype_fp = by_type_breakdown(
            [], dg_missing, dg_fp_list, expected)

        print(f"\n  Per-type recall:")
        for t in sorted(all_types):
            tp_t = type_total[t] - dgtype_fn[t]
            rec_t = tp_t / type_total[t] if type_total[t] else 0
            b_rec_t = (type_total[t] - btype_fn[t]) / type_total[t] if type_total[t] else 0
            flag = "✅" if rec_t >= 0.5 else ("⚠️" if rec_t > 0 else "❌")
            delta = rec_t - b_rec_t
            delta_str = f"  Δ+{delta:.0%}" if delta > 0 else (f"  Δ{delta:.0%}" if delta < 0 else "")
            print(f"    {flag}  {t:<28}  {tp_t}/{type_total[t]}  ({rec_t:.0%}){delta_str}")

        if dg_missing:
            print(f"\n  Missed findings ({dg_fn}):")
            for m in dg_missing:
                print(f"    {normalize(m['file'])}:{m['line']:3d}  [{m['type']}]  {m['description'][:60]}")

        # Type-agnostic detection (wide tolerance): answers "was the vuln detected in any form?"
        # Known issue: type-constrained matching misses findings where the LLM reported the right
        # location but wrong type (e.g. SSRF labelled auth_issue), or right type but with a
        # chunk-offset line shift.  This view removes both constraints to show raw detection power.
        hdr("Deep-Guard — Type-Agnostic Detection (wide tolerance, diagnosis view)")
        dg_all_findings = [
            {"file": f["file"], "line": f["line"], "type": None,
             "severity": f["severity"], "confidence": f.get("confidence", 0)}
            for f in dg_raw
        ]
        dg2_tp, dg2_fp_list, dg2_missing = match(expected, dg_all_findings, LINE_TOL_DG_WIDE,
                                                   require_type=False)
        dg2_fp = len(dg2_fp_list)
        dg2_fn = len(dg2_missing)
        dg2_p, dg2_r, dg2_f = metrics(dg2_tp, dg2_fp, dg2_fn)
        print(f"  Tolerance: ±{LINE_TOL_DG_WIDE} lines, any type label accepted")
        print(f"  TP={dg2_tp}  FP={dg2_fp}  FN={dg2_fn}")
        print(f"  Precision={dg2_p:.3f}  Recall={dg2_r:.3f}  F1={dg2_f:.3f}")
        print(f"\n  Interpretation:")
        print(f"    Recall={dg2_r:.3f} is the fraction of vulnerabilities the LLM semantically")
        print(f"    detected regardless of how it labelled the type or which exact line it")
        print(f"    reported. The gap vs type-constrained (Recall={dg_r:.3f}) shows how much")
        print(f"    recall is lost to type-misclassification and line-attribution drift.")
        if dg2_missing:
            print(f"\n  Still missed even with wide tolerance ({len(dg2_missing)}):")
            for m in dg2_missing:
                print(f"    {normalize(m['file'])}:{m['line']:3d}  [{m['type']}]  {m['description'][:60]}")

        dg_available = True

    # ── COMPARISON TABLE ─────────────────────────────────────────────────────
    hdr("Comparison Table")
    w = 74
    print(f"{'Tool':<26} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>6} {'Rec':>6} {'F1':>6}")
    print("─" * w)

    def row(name, tp_, fp_, fn_):
        p, r, f = metrics(tp_, fp_, fn_)
        return f"{name:<26} {tp_:>3} {fp_:>3} {fn_:>3} {p:>6.3f} {r:>6.3f} {f:>6.3f}"

    print(row("Bandit 1.8.6", b_tp, b_fp, b_fn))
    if dg_available:
        print(row("Deep-Guard (type-constrained)", dg_tp, dg_fp, dg_fn))
        print(row("Deep-Guard (type-agnostic det.)", dg2_tp, dg2_fp, dg2_fn))

    print(f"\n  Type-constrained uses ±{LINE_TOL_DG}L tolerance + exact type match.")
    print(f"  Type-agnostic uses ±{LINE_TOL_DG_WIDE}L, any label — measures raw detection power.")

    # ── BLIND SPOTS SUMMARY ──────────────────────────────────────────────────
    hdr("Bandit Blind Spots by Category")
    blind = golden.get("bandit_summary", {}).get("bandit_blind_spots", {})
    for vuln_type, reason in blind.items():
        print(f"  {vuln_type:<20}  {reason}")

    print("""
Why the gap exists:
  Bandit is an AST-visitor that pattern-matches individual statements.
  It cannot:
    – Trace data from request.args through function calls to HTTP clients (SSRF)
    – Understand that concatenating user input before render_template_string
      defeats Jinja2's autoescaping (XSS)
    – Know the semantics of jwt.decode(algorithms=None) (JWT)
    – Follow the path from request.args → os.path.join → send_file (path traversal)

  Deep-Guard's LLM reads the semantic intent of code. It understands that
  "fetch a URL the user supplies" is SSRF regardless of which HTTP library
  is used, and that "join user input onto a base path without os.path.basename
  or os.path.normpath" is path traversal regardless of API shape.
""")


if __name__ == "__main__":
    main()
