#!/usr/bin/env python3
"""
Zero-shot GPT-4 baseline for the JS/TS SQL injection benchmark.

Sends each benchmark file directly to GPT-4 with a minimal security review
prompt — NO KB retrieval, NO RAG context, NO framework-aware hints.

This is the ablation study that answers:
  "Does Deep-Guard's architecture (AST chunking + KB/RAG + framework hints)
   add value over simply asking GPT-4 to review the code?"

Usage:
  # Annotated benchmark (VULN comments visible — upper-bound comparison):
  DEEPGUARD_OPENAI_API_KEY=<key> python3 scripts/zero_shot_baseline.py
  python3 scripts/evaluation_report.py --results test-samples/js-ts-sqli/zero-shot-results.json

  # CLEAN benchmark (annotation-stripped — fair comparison, no comment leakage):
  DEEPGUARD_OPENAI_API_KEY=<key> python3 scripts/zero_shot_baseline.py \\
      --bench-dir test-samples/js-ts-sqli-clean
  python3 scripts/evaluation_report.py \\
      --results test-samples/js-ts-sqli-clean/zero-shot-results.json \\
      --golden  test-samples/js-ts-sqli-clean/expected-findings.json

NOTE on benchmark contamination:
  The original js-ts-sqli files contain inline annotations (// VULN: SQL Injection,
  // Line 19: Critical SQLi) that label every vulnerability for human readers.
  Zero-shot GPT-4 reads these comments and scores F1≈0.99 on the annotated files —
  NOT because of code analysis but because the comments name the vulnerabilities.
  Use --bench-dir js-ts-sqli-clean for a contamination-free comparison.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT  = Path(__file__).parent.parent

_parser = argparse.ArgumentParser(description="Zero-shot GPT-4 baseline")
_parser.add_argument("--bench-dir", default=None,
                     help="Benchmark directory (default: test-samples/js-ts-sqli)")
_args, _ = _parser.parse_known_args()

if _args.bench_dir:
    BENCH_DIR = Path(_args.bench_dir)
    if not BENCH_DIR.is_absolute():
        BENCH_DIR = REPO_ROOT / BENCH_DIR
else:
    BENCH_DIR = REPO_ROOT / "test-samples/js-ts-sqli"

OUTPUT = BENCH_DIR / "zero-shot-results.json"

API_URL = "https://api.gapgpt.app/v1/chat/completions"
API_KEY = os.environ.get("DEEPGUARD_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
MODEL   = "gpt-4o"

# Exactly the same type vocabulary as Deep-Guard — fair apples-to-apples
ALLOWED_TYPES = (
    "sql_injection command_injection path_traversal ssrf xss "
    "crypto_issue insecure_deserialization insecure_secret xxe_injection"
)

# ── Prompts ───────────────────────────────────────────────────────────────────
# Intentionally minimal — no KB context, no framework hints, no examples.
SYSTEM = (
    "You are a security code reviewer. "
    "Identify security vulnerabilities in code and return structured JSON findings."
)

USER_TMPL = """\
Analyze the following code for security vulnerabilities.

Return ONLY a valid JSON object — no markdown fences, no explanation outside the JSON.
Schema:
{{
  "findings": [
    {{
      "type": "<one of: {types}>",
      "line": <integer line number where the vulnerability occurs>,
      "severity": "<critical|high|medium|low>",
      "confidence": <float 0.0–1.0>,
      "message": "<concise description of the vulnerability>"
    }}
  ]
}}

Return {{"findings": []}} if the code is clean.

File: {filename}
{numbered_code}"""


def number_lines(code: str) -> str:
    lines = code.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{i+1:{width}d}: {line}" for i, line in enumerate(lines))


def call_api(messages: list, retries: int = 2) -> dict:
    import urllib.request
    body = json.dumps({
        "model": MODEL,
        "messages": messages,
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
        method="POST",
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except Exception as e:
            if attempt == retries:
                raise
            print(f"  retry {attempt+1}: {e}")
            time.sleep(2)


def scan_file(path: Path) -> tuple[list[dict], float]:
    code = path.read_text(encoding="utf-8")
    numbered = number_lines(code)
    user_msg = USER_TMPL.format(
        types=ALLOWED_TYPES,
        filename=path.name,
        numbered_code=numbered,
    )
    resp = call_api([
        {"role": "system", "content": SYSTEM},
        {"role": "user",   "content": user_msg},
    ])
    usage = resp.get("usage", {})
    pt = usage.get("prompt_tokens", 0)
    ct = usage.get("completion_tokens", 0)
    # gpt-4o pricing: $5/1M input, $15/1M output
    cost = pt * 5e-6 + ct * 15e-6

    raw = resp["choices"][0]["message"]["content"]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # strip accidental markdown fences
        import re
        cleaned = re.sub(r"```[a-z]*\n?", "", raw).strip()
        data = json.loads(cleaned)

    findings = []
    for f in data.get("findings", []):
        findings.append({
            "file": str(path),
            "line": int(f.get("line", 0)),
            "type": f.get("type", "unknown"),
            "severity": f.get("severity", "medium"),
            "confidence": float(f.get("confidence", 0.5)),
            "message": f.get("message", ""),
            "recommendation": "",
        })
    return findings, cost


def main():
    if not API_KEY:
        print("ERROR: set DEEPGUARD_OPENAI_API_KEY", file=sys.stderr)
        sys.exit(1)

    js_ts_files = sorted(
        p for p in BENCH_DIR.iterdir()
        if p.suffix in {".js", ".ts"} and p.name != "expected-findings.json"
    )
    if not js_ts_files:
        print(f"ERROR: no JS/TS files found in {BENCH_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"Zero-shot GPT-4 baseline — {len(js_ts_files)} files, model={MODEL}")
    print(f"NO KB context · NO RAG · NO framework hints\n")

    all_findings: list[dict] = []
    total_cost = 0.0

    for path in js_ts_files:
        print(f"  scanning {path.name} ... ", end="", flush=True)
        findings, cost = scan_file(path)
        all_findings.extend(findings)
        total_cost += cost
        print(f"{len(findings)} findings  (${cost:.4f})")

    report = {
        "scan_metadata": {
            "target_path": str(BENCH_DIR),
            "model": MODEL,
            "mode": "zero_shot_no_kb_no_rag",
            "total_cost": total_cost,
            "files_scanned": len(js_ts_files),
        },
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "by_severity": {},
            "by_type":     {},
        },
    }
    for f in all_findings:
        report["summary"]["by_severity"][f["severity"]] = \
            report["summary"]["by_severity"].get(f["severity"], 0) + 1
        report["summary"]["by_type"][f["type"]] = \
            report["summary"]["by_type"].get(f["type"], 0) + 1

    OUTPUT.write_text(json.dumps(report, indent=2))
    print(f"\nDone — {len(all_findings)} total findings, cost ${total_cost:.4f}")
    print(f"Saved → {OUTPUT.relative_to(REPO_ROOT)}")
    print(f"\nEvaluate with:")
    print(f"  python3 scripts/evaluation_report.py --results {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
