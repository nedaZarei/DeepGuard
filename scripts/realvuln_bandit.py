#!/usr/bin/env python3
"""
Run Bandit on the RealVuln Python repos and write Semgrep-format results the
RealVuln scorer reads, to $RV/scan-results/<repo>/bandit/results.json.

Bandit runs with its defaults (all tests, all severities and confidences); each
issue keeps the CWE Bandit itself assigns. Committed virtualenvs are excluded,
the same scope as the .deepguardignore used for the DeepGuard runs.

Usage: RV=/path/to/Real-Vuln-Benchmark python3 scripts/realvuln_bandit.py [repo ...]
Then:  python3 scripts/realvuln_stats.py --slugs bandit ... --repos ...
"""
import glob
import json
import os
import subprocess
import sys

RV = os.environ.get("RV") or sys.exit("set RV to the Real-Vuln-Benchmark checkout")
EXCLUDE = "*/.venv/*,*/venv/*"
SEVERITY_MAP = {"HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "INFO"}


def python_repos() -> list[str]:
    out = []
    for p in sorted(glob.glob(f"{RV}/ground-truth/realvuln-*/ground-truth.json")):
        if json.load(open(p)).get("language") == "python":
            out.append(p.split("/")[-2])
    return out


def convert(report: dict, root: str) -> dict:
    results = []
    for issue in report.get("results", []):
        cwe = (issue.get("issue_cwe") or {}).get("id")
        results.append({
            "check_id": f"bandit.{issue['test_id']}.{issue['test_name']}",
            "path": os.path.relpath(issue["filename"], root).replace("\\", "/"),
            "start": {"line": issue["line_number"], "col": 1},
            "end": {"line": issue["line_number"], "col": 1},
            "extra": {
                "message": issue.get("issue_text", ""),
                "severity": SEVERITY_MAP.get(issue.get("issue_severity"), "INFO"),
                "metadata": {"cwe": [f"CWE-{cwe}"] if cwe else [], "confidence": issue.get("issue_confidence")},
            },
        })
    return {"results": results, "errors": report.get("errors", []), "version": "bandit"}


def main() -> int:
    version = subprocess.run(["bandit", "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    print(version)
    for repo in sys.argv[1:] or python_repos():
        root = f"{RV}/repos/{repo}"
        if not os.path.isdir(root):
            print(f"skip {repo} (not cloned)")
            continue
        # Bandit exits 1 when it finds issues, so the return code is not an error signal.
        proc = subprocess.run(["bandit", "-r", root, "-f", "json", "-q", "-x", EXCLUDE],
                              capture_output=True, text=True)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            print(f"{repo}: bandit failed: {proc.stderr.strip()[:200]}")
            return 1
        out = convert(report, root)
        dst = f"{RV}/scan-results/{repo}/bandit"
        os.makedirs(dst, exist_ok=True)
        json.dump(out, open(f"{dst}/results.json", "w"), indent=2)
        print(f"{repo}: {len(out['results'])} findings, {len(out['errors'])} files Bandit could not parse")
    return 0


if __name__ == "__main__":
    sys.exit(main())
