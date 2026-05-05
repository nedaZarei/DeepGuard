#!/usr/bin/env python3
"""
Compare SonarQube findings vs Deep-Guard findings on the js-ts-sqli evaluation dataset.
Usage: python3 scripts/compare_sonar.py --sonar <sonar_issues.json> --deepguard <scan_report.json>
"""
import json
import sys
import argparse

GROUND_TRUTH = [
    ("express-routes.js", 19, "sql_injection"),
    ("express-routes.js", 31, "sql_injection"),
    ("express-routes.js", 45, "sql_injection"),
    ("express-routes.js", 63, "sql_injection"),
    ("express-complex.js", 29, "sql_injection"),
    ("express-complex.js", 33, "sql_injection"),
    ("express-complex.js", 37, "sql_injection"),
    ("express-complex.js", 58, "sql_injection"),
    ("express-complex.js", 77, "sql_injection"),
    ("express-complex.js", 93, "sql_injection"),
    ("prisma-service.js", 12, "sql_injection"),
    ("prisma-service.js", 19, "sql_injection"),
    ("prisma-service.js", 26, "sql_injection"),
    ("prisma-service.js", 35, "sql_injection"),
    ("prisma-service.js", 54, "sql_injection"),
    ("prisma-service.js", 57, "sql_injection"),
    ("prisma-service.js", 66, "sql_injection"),
    ("prisma-unsafe.js", 11, "sql_injection"),
    ("prisma-unsafe.js", 17, "sql_injection"),
    ("prisma-unsafe.js", 29, "sql_injection"),
    ("prisma-unsafe.js", 47, "sql_injection"),
    ("prisma-unsafe.js", 59, "sql_injection"),
    ("sequelize-models.js", 27, "sql_injection"),
    ("sequelize-models.js", 35, "sql_injection"),
    ("sequelize-models.js", 48, "sql_injection"),
    ("sequelize-models.js", 61, "sql_injection"),
    ("sequelize-models.js", 69, "sql_injection"),
    ("sequelize-dynamic.js", 14, "sql_injection"),
    ("sequelize-dynamic.js", 23, "sql_injection"),
    ("sequelize-dynamic.js", 36, "sql_injection"),
    ("sequelize-dynamic.js", 50, "sql_injection"),
    ("sequelize-dynamic.js", 63, "sql_injection"),
    ("sequelize-dynamic.js", 72, "sql_injection"),
    ("typescript-express.ts", 34, "sql_injection"),
    ("typescript-express.ts", 52, "sql_injection"),
    ("typescript-express.ts", 73, "sql_injection"),
    ("typescript-express.ts", 96, "sql_injection"),
    ("typescript-prisma.ts", 26, "sql_injection"),
    ("typescript-prisma.ts", 32, "sql_injection"),
    ("typescript-prisma.ts", 43, "sql_injection"),
    ("typescript-prisma.ts", 63, "sql_injection"),
    ("typescript-prisma.ts", 73, "sql_injection"),
    ("typescript-prisma.ts", 92, "sql_injection"),
    ("typescript-prisma.ts", 116, "sql_injection"),
    ("typescript-prisma.ts", 122, "sql_injection"),
]

LINE_TOLERANCE = 10


def match_findings(findings, tolerance=LINE_TOLERANCE):
    """Match findings against ground truth. Returns (tp, fp, fn, precision, recall, f1)."""
    matched_det = set()
    tp = 0
    for gt_file, gt_line, _ in GROUND_TRUTH:
        best_diff, best_i = 9999, -1
        for i, (f_file, f_line) in enumerate(findings):
            if i in matched_det:
                continue
            if f_file == gt_file and abs(f_line - gt_line) <= tolerance:
                diff = abs(f_line - gt_line)
                if diff < best_diff:
                    best_diff, best_i = diff, i
        if best_i >= 0:
            tp += 1
            matched_det.add(best_i)

    fp = len(findings) - tp
    fn = len(GROUND_TRUTH) - tp
    p = tp / len(findings) if findings else 0
    r = tp / len(GROUND_TRUTH)
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    return tp, fp, fn, round(p, 3), round(r, 3), round(f1, 3)


def file_level(findings):
    gt_files = set(f for f, _, _ in GROUND_TRUTH)
    det_files = set(f for f, _ in findings)
    tp = len(gt_files & det_files)
    fp = len(det_files - gt_files)
    fn = len(gt_files - det_files)
    p = tp / len(det_files) if det_files else 0
    r = tp / len(gt_files)
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    return tp, fp, fn, round(p, 3), round(r, 3), round(f1, 3), gt_files, det_files


def load_sonar(path):
    """Parse SonarQube issues API JSON into (filename, line) tuples."""
    with open(path) as f:
        data = json.load(f)
    issues = data.get("issues", data) if isinstance(data, dict) else data
    findings = []
    for issue in issues:
        component = issue.get("component", "")
        fname = component.split(":")[-1].split("/")[-1]
        line = issue.get("line", issue.get("textRange", {}).get("startLine", 0))
        rule = issue.get("rule", "")
        findings.append((fname, line, rule))
    return findings


def load_deepguard(path):
    """Parse Deep-Guard JSON report into (filename, line) tuples for sql_injection only."""
    with open(path) as f:
        report = json.load(f)
    findings = []
    for f in report.get("findings", []):
        if f.get("type") == "sql_injection":
            fname = f.get("file", "").split("/")[-1]
            line = f.get("line", 0)
            findings.append((fname, line))
    return findings


def print_table(label, tp, fp, fn, p, r, f1):
    print(f"  {label:<12} | TP={tp:2d}  FP={fp:2d}  FN={fn:2d} | P={p:.3f}  R={r:.3f}  F1={f1:.3f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sonar", required=True, help="SonarQube issues JSON file")
    parser.add_argument("--deepguard", required=True, help="Deep-Guard scan report JSON")
    args = parser.parse_args()

    sonar_raw = load_sonar(args.sonar)
    sonar_sqli = [(f, l) for f, l, r in sonar_raw
                  if any(k in r.lower() for k in ["sql", "injection", "sqli"])]
    sonar_all = [(f, l) for f, l, r in sonar_raw]

    dg_sqli = load_deepguard(args.deepguard)

    print(f"\n{'='*65}")
    print(f"  SONARQUBE vs DEEP-GUARD — SQL Injection Evaluation")
    print(f"  Ground truth: {len(GROUND_TRUTH)} labeled findings across 8 files")
    print(f"  Line tolerance: ±{LINE_TOLERANCE}")
    print(f"{'='*65}\n")

    print(f"  Tool           | Total detected | SQL-injection specific")
    print(f"  {'-'*55}")
    print(f"  SonarQube      | {len(sonar_all):14d} | {len(sonar_sqli)}")
    print(f"  Deep-Guard     | (see report)   | {len(dg_sqli)}")

    print(f"\n--- Finding-level (±{LINE_TOLERANCE} lines, SQL injection only) ---")
    sq_tp, sq_fp, sq_fn, sq_p, sq_r, sq_f1 = match_findings(sonar_sqli)
    dg_tp, dg_fp, dg_fn, dg_p, dg_r, dg_f1 = match_findings(dg_sqli)
    print_table("SonarQube", sq_tp, sq_fp, sq_fn, sq_p, sq_r, sq_f1)
    print_table("Deep-Guard", dg_tp, dg_fp, dg_fn, dg_p, dg_r, dg_f1)

    print(f"\n--- File-level (which files flagged correctly) ---")
    sq_ftp, sq_ffp, sq_ffn, sq_fp2, sq_fr, sq_ff1, gt_files, sq_files = file_level(sonar_sqli)
    dg_ftp, dg_ffp, dg_ffn, dg_fp3, dg_fr, dg_ff1, _, dg_files = file_level(dg_sqli)
    print_table("SonarQube", sq_ftp, sq_ffp, sq_ffn, sq_fp2, sq_fr, sq_ff1)
    print_table("Deep-Guard", dg_ftp, dg_ffp, dg_ffn, dg_fp3, dg_fr, dg_ff1)

    print(f"\n--- Files Deep-Guard found that SonarQube missed ---")
    missed_by_sonar = dg_files - sq_files
    if missed_by_sonar:
        for f in sorted(missed_by_sonar):
            print(f"  + {f}")
    else:
        print("  (none)")

    print(f"\n--- All SonarQube issue rules detected ---")
    rule_counts = {}
    for _, _, r in sonar_raw:
        rule_counts[r] = rule_counts.get(r, 0) + 1
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {count:3d}x  {rule}")

    print()


if __name__ == "__main__":
    main()
