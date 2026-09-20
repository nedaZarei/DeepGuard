#!/usr/bin/env python3
"""
Convert a DeepGuard scan report into Semgrep-format JSON for the RealVuln scorer.

RealVuln (https://github.com/kolega-ai/Real-Vuln-Benchmark) matches findings on
file path + CWE + line (±10). DeepGuard reports a vulnerability *type*, not a CWE,
so this adapter maps each type to the single CWE that maximises coverage of the
benchmark's acceptable_cwes lists (derived from the 26 human-authored repos).

Only ONE CWE is emitted per finding: the Semgrep parser creates one finding per
CWE, and every unmatched one would count as a false positive.

Usage:
  python3 scripts/realvuln_adapter.py <deepguard-report.json> <repo-root> <out.json>
"""
import json
import os
import sys

# DeepGuard type -> CWE.  Coverage figures are against RealVuln human-authored GT.
TYPE_TO_CWE = {
    "sql_injection":            "CWE-89",   # 47/47
    "xss":                      "CWE-79",   # 84/84
    "command_injection":        "CWE-78",   # 18/30 (rest are code_injection CWE-94)
    "ssrf":                     "CWE-918",  # 24/24
    "path_traversal":           "CWE-22",   # 26/32
    "insecure_deserialization": "CWE-502",  # 19/19
    "xxe":                      "CWE-611",  # 8/8
    "auth_issue":               "CWE-284",  # 56/78
    "crypto_issue":             "CWE-327",  # 17/32
}

SEVERITY_MAP = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}


def to_repo_relative(path: str, target_path: str, repo_root: str) -> str:
    """Make a finding's path relative to the repo root the scorer expects.

    DeepGuard writes paths as `<--path argument>/<file>`, relative or absolute
    depending on how it was invoked. The report's own `target_path` is the
    authoritative prefix: a benchmark checkout may have moved since the scan,
    so relpath against the *current* repo_root would silently produce
    `../../..` paths and zero matches. Order: strip target_path; else, if
    absolute, relpath against repo_root; then drop any leading `./`.
    """
    p = path.replace("\\", "/")
    tp = (target_path or "").replace("\\", "/").rstrip("/")
    if tp and (p == tp or p.startswith(tp + "/")):
        p = p[len(tp):].lstrip("/")
    elif os.path.isabs(p):
        p = os.path.relpath(p, repo_root).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def convert(report: dict, repo_root: str, conf_min: float = 0.0) -> dict:
    target_path = report.get("scan_metadata", {}).get("target_path", "")
    results = []
    skipped = {}
    # `or []` matters: a zero-finding scan writes "findings": null, and
    # .get(key, default) returns None for an explicit null rather than the default.
    for f in (report.get("findings") or []):
        if f.get("confidence", 1.0) < conf_min:
            continue
        cwe = TYPE_TO_CWE.get(f.get("type"))
        if not cwe:
            skipped[f.get("type")] = skipped.get(f.get("type"), 0) + 1
            continue
        results.append({
            "check_id": f"deepguard.{f['type']}",
            "path": to_repo_relative(f["file"], target_path, repo_root),
            "start": {"line": f["line"], "col": 1},
            "end":   {"line": f["line"], "col": 1},
            "extra": {
                "message": f.get("message", ""),
                "severity": SEVERITY_MAP.get(f.get("severity", "medium"), "WARNING"),
                "metadata": {
                    "cwe": [cwe],
                    "confidence": f.get("confidence"),
                    "deepguard_type": f.get("type"),
                    "function": f.get("function_name"),
                },
            },
        })
    if skipped:
        print(f"  note: skipped types with no CWE mapping: {skipped}", file=sys.stderr)
    return {"results": results, "errors": [], "version": "deepguard-adapter-1.0"}


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    src, repo_root, dst = sys.argv[1:4]
    with open(src) as fh:
        report = json.load(fh)
    # REALVULN_CONF_MIN lets us sweep the confidence threshold at scoring time
    # without re-running the (slow) scan; the raw report keeps everything >= 0.5.
    out = convert(report, repo_root, float(os.environ.get("REALVULN_CONF_MIN", "0")))
    escaped = [r["path"] for r in out["results"] if r["path"].startswith("../") or os.path.isabs(r["path"])]
    if escaped:
        print(f"  ERROR: {len(escaped)} finding paths are not repo-relative (e.g. {escaped[0][:80]}); "
              "target_path in the report does not match its findings", file=sys.stderr)
        sys.exit(2)
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  wrote {len(out['results'])} findings -> {dst}")


if __name__ == "__main__":
    main()
