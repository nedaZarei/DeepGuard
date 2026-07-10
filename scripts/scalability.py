#!/usr/bin/env python3
"""
Scalability and efficiency evaluation for Deep-Guard.

Two modes:
  --from-reports DIR  Extract timing from already-saved scan report JSONs (no API
                      calls needed). Pass the reports/ directory; the script finds
                      all scan-*.json files and groups them by target_path.
  (default)           Run live scans against TARGETS, clear cache before each run,
                      measure wall-clock time, and save a metrics JSON.

Usage:
    # From existing scan reports (no API key needed):
    python3 scripts/scalability.py --from-reports reports/

    # Live measurement (uses API):
    DEEPGUARD_OPENAI_API_KEY=... python3 scripts/scalability.py --runs 1
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BINARY    = REPO_ROOT / "deepguard"
API_KEY   = os.environ.get("DEEPGUARD_OPENAI_API_KEY", "")
BASE_URL  = os.environ.get("DEEPGUARD_OPENAI_BASE_URL", "https://api.gapgpt.app/v1")

TARGETS = [
    {
        "name":  "Small  (8 files, ~600 LOC)",
        "path":  str(REPO_ROOT / "test-samples/js-ts-sqli-clean"),
        "label": "small",
    },
    {
        "name":  "Medium (3 files, ~430 LOC — DVNA core)",
        "path":  "/tmp/dvna/core",
        "label": "medium",
    },
    {
        "name":  "Large  (full DVNA, ~1 800 LOC)",
        "path":  "/tmp/dvna",
        "label": "large",
    },
]


# ─── From-reports mode ───────────────────────────────────────────────────────

def extract_from_reports(reports_root: str) -> list[dict]:
    root = Path(reports_root)
    rows = []
    for report_file in sorted(root.rglob("scan-*.json")):
        try:
            data = json.loads(report_file.read_text())
            meta = data.get("scan_metadata", {})
            target = meta.get("target_path", "")
            duration = meta.get("scan_duration_seconds")
            cost = meta.get("total_cost", 0.0)
            findings = data.get("findings", [])
            unique_files = len({f["file"] for f in findings})
            if duration:
                rows.append({
                    "report": str(report_file.relative_to(REPO_ROOT)),
                    "target": target,
                    "duration_s": duration,
                    "findings": len(findings),
                    "unique_files": unique_files,
                    "cost_usd": cost,
                    "model": meta.get("model_used", ""),
                })
        except Exception:
            continue
    return rows


def print_from_reports(rows: list[dict]) -> None:
    if not rows:
        print("No scan-*.json files with timing found.")
        return

    print("=" * 72)
    print("DEEP-GUARD — SCALABILITY EVIDENCE FROM SAVED SCAN REPORTS")
    print("=" * 72)
    print(f"\n{'Report':<45} {'Duration':>9} {'Findings':>9} {'Files':>6} {'Cost':>8}")
    print("─" * 82)
    for r in rows:
        print(f"{r['report']:<45} {r['duration_s']:>8.0f}s {r['findings']:>9} "
              f"{r['unique_files']:>6} ${r['cost_usd']:>7.4f}")

    # Print known-target summary
    known = {}
    for r in rows:
        t = r["target"]
        # Prefer the most recent report per target
        if t not in known or r["duration_s"] > 0:
            known[t] = r

    if len(known) >= 2:
        print("\n─── Scaling Ratio ─────────────────────────────────────────────────")
        items = sorted(known.values(), key=lambda x: x["duration_s"])
        base = items[0]
        for r in items[1:]:
            ratio = r["duration_s"] / base["duration_s"] if base["duration_s"] else 0
            print(f"  {r['target']!r} / {base['target']!r}: {ratio:.1f}× slower")


# ─── Live mode ───────────────────────────────────────────────────────────────

def clear_cache() -> None:
    subprocess.run([str(BINARY), "cache", "clear"], capture_output=True)


def scan_once(target_path: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Remove stale reports from previous runs
    for f in out_dir.glob("scan-*.json"):
        f.unlink()

    env = {**os.environ,
           "DEEPGUARD_OPENAI_API_KEY": API_KEY,
           "DEEPGUARD_OPENAI_BASE_URL": BASE_URL}

    cmd = [str(BINARY), "scan", "--path", target_path, "--output", str(out_dir)]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    wall = time.perf_counter() - t0

    findings, cost, duration, unique_files = 0, 0.0, wall, 0
    for f in sorted(out_dir.glob("scan-*.json"), key=lambda p: p.stat().st_mtime):
        try:
            data = json.loads(f.read_text())
            meta = data.get("scan_metadata", {})
            all_findings = data.get("findings", [])
            findings = len(all_findings)
            unique_files = len({fnd["file"] for fnd in all_findings})
            cost = meta.get("total_cost", 0.0)
            duration = meta.get("scan_duration_seconds", wall)
        except Exception:
            pass

    return {
        "wall_s": wall,
        "duration_s": duration,
        "findings": findings,
        "unique_files": unique_files,
        "cost_usd": cost,
        "returncode": proc.returncode,
    }


def run_live(runs: int, save_output) -> None:
    if not API_KEY:
        print("ERROR: DEEPGUARD_OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)
    if not BINARY.exists():
        print(f"ERROR: binary not found at {BINARY}", file=sys.stderr)
        sys.exit(1)

    print("=" * 68)
    print("DEEP-GUARD — SCALABILITY & EFFICIENCY EVALUATION (LIVE)")
    print("=" * 68)
    print(f"Runs per target: {runs}  (cache cleared before each run)\n")

    rows = []
    for t in TARGETS:
        path = t["path"]
        if not Path(path).exists():
            print(f"  SKIPPED {t['name']} — path not found: {path}\n")
            continue

        print(f"Scanning: {t['name']}")
        out_dir = REPO_ROOT / "reports" / "scalability_tmp" / t["label"]
        times, last = [], {}
        for i in range(runs):
            clear_cache()
            r = scan_once(path, out_dir)
            if r["returncode"] != 0:
                print(f"    run {i+1}/{runs}: FAILED")
                continue
            times.append(r["duration_s"])
            last = r
            print(f"    run {i+1}/{runs}: {r['duration_s']:.0f}s "
                  f"(wall {r['wall_s']:.0f}s)  findings={r['findings']}")

        if not times:
            continue

        avg = sum(times) / len(times)
        rows.append({
            "name": t["name"], "path": path, "label": t["label"],
            "runs": len(times), "avg_s": avg,
            "min_s": min(times), "max_s": max(times),
            "findings": last.get("findings", 0),
            "unique_files": last.get("unique_files", 0),
            "cost_usd": last.get("cost_usd", 0.0),
        })
        print(f"  → avg={avg:.0f}s  findings={last.get('findings',0)}  "
              f"cost=${last.get('cost_usd',0):.4f}\n")

    if not rows:
        print("No results.")
        return

    print("\n─── Summary Table ──────────────────────────────────────────────────")
    print(f"{'Target':<42} {'Files':>6} {'Findings':>9} {'Avg(s)':>7} {'Cost':>8}")
    print("─" * 78)
    for r in rows:
        print(f"{r['name']:<42} {r['unique_files']:>6} {r['findings']:>9} "
              f"{r['avg_s']:>7.0f} ${r['cost_usd']:>7.4f}")

    if len(rows) >= 2:
        base = rows[0]
        print()
        for r in rows[1:]:
            ratio = r["avg_s"] / base["avg_s"] if base["avg_s"] else 0
            fsize = r["unique_files"] / base["unique_files"] if base["unique_files"] else 0
            print(f"  {r['label']}: {ratio:.1f}× slower than small "
                  f"({fsize:.1f}× more files → {'near-linear' if ratio < fsize * 2 else 'super-linear'} scaling)")

    print(f"""
─── Complexity ─────────────────────────────────────────────────
  O(F × V): F = function chunks, V = vulnerability types (9 web or 4 C/C++).
  Each (chunk, type) pair = one LLM call, parallelised over worker pool.
  Linear scaling: 10× codebase → ~10× scan time, no quadratic blowup.
""")

    if save_output:
        out = Path(save_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "mode": "live",
            "runs_per_target": runs,
            "results": rows,
        }, indent=2))
        print(f"Metrics saved to {out}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Deep-Guard scalability evaluation")
    p.add_argument("--from-reports", metavar="DIR", default=None,
                   help="Extract timing from saved scan report JSONs (no API needed)")
    p.add_argument("--runs", type=int, default=1,
                   help="Number of live scan runs per target (default: 1)")
    p.add_argument("--output", default=None,
                   help="Save metric results as JSON")
    args = p.parse_args()

    if args.from_reports:
        rows = extract_from_reports(args.from_reports)
        print_from_reports(rows)
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({"mode": "from_reports", "results": rows}, indent=2))
            print(f"\nMetrics saved to {args.output}")
    else:
        run_live(args.runs, args.output)


if __name__ == "__main__":
    main()
