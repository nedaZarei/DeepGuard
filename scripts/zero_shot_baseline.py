#!/usr/bin/env python3
"""
Zero-shot baseline: the model reads each file directly, with no pipeline.

No AST chunking, no KB retrieval / RAG, no framework hints, no per-type
templates — one minimal prompt per file. This is the control that answers:
  "Does DeepGuard's architecture add value over simply asking the model?"

Works against any OpenAI-compatible endpoint (OpenAI, GapGPT, Groq, local
Ollama) and any language DeepGuard scans. Output is a DeepGuard-shaped scan
report so the same evaluation scripts (evaluation_report.py,
realvuln_adapter.py) consume it unchanged.

Usage:
  # JS/TS benchmark (thesis-era usage, unchanged):
  DEEPGUARD_OPENAI_API_KEY=<key> python3 scripts/zero_shot_baseline.py \\
      --bench-dir test-samples/js-ts-sqli-clean

  # A RealVuln repo with the local 7B model:
  DEEPGUARD_OPENAI_BASE_URL=http://localhost:11434/v1 DEEPGUARD_OPENAI_API_KEY=ollama \\
  python3 scripts/zero_shot_baseline.py --bench-dir ~/Real-Vuln-Benchmark/repos/realvuln-dsvw \\
      --lang py --model qwen2.5-coder:7b --output reports/realvuln/zeroshot-qwen7b/realvuln-dsvw/scan.json

NOTE on benchmark contamination (JS/TS): the original js-ts-sqli files carry
inline "// VULN:" annotations; use js-ts-sqli-clean for a fair comparison.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

# urllib's default User-Agent is rejected by Cloudflare in front of some providers
# (Groq returns 403 "error code: 1010"); identify the client explicitly.
USER_AGENT = "DeepGuard-research/0.1 (+https://github.com/nedaZarei/DeepGuard)"
REPO_ROOT = Path(__file__).resolve().parent.parent

# Same 9 type names as DeepGuard's Python/JS templates, so type-constrained
# scoring and the RealVuln adapter's type->CWE map apply to both systems alike.
ALLOWED_TYPES = (
    "sql_injection xss path_traversal insecure_deserialization auth_issue "
    "crypto_issue command_injection ssrf xxe_injection"
)

LANG_EXT = {"js": {".js", ".ts"}, "py": {".py"}, "java": {".java"}}
SKIP_DIRS = {"node_modules", "venv", ".venv", "site-packages", "migrations",
             "__pycache__", ".git", "dist", "build", "tests", "test"}

# Rough guard so a whole-file prompt fits the serving context (chars/4 ~ tokens).
MAX_PROMPT_TOKENS_DEFAULT = 6000

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
      "confidence": <float 0.0-1.0>,
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
    return "\n".join(f"{i + 1:{width}d}: {line}" for i, line in enumerate(lines))


def price(model: str, pt: int, ct: int) -> float:
    m = model.lower()
    if m.startswith("gpt-4o-mini"):
        return pt * 0.15e-6 + ct * 0.60e-6
    if m.startswith("gpt-4o"):
        return pt * 2.5e-6 + ct * 10e-6
    return 0.0  # open-weight / local


def call_api(base_url: str, api_key: str, model: str, messages: list,
             timeout: int, retries: int = 2, json_mode: bool = True, max_tokens: int = 2048) -> dict:
    # Cap generation: a small model in JSON mode on a dense file can otherwise emit
    # findings until the context is exhausted, then time out and retry.
    payload = {"model": model, "messages": messages, "temperature": 0, "max_tokens": max_tokens}
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}", "User-Agent": USER_AGENT},
        method="POST",
    )
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except Exception as e:  # noqa: BLE001 - surface after retries
            if attempt == retries:
                raise
            print(f"  retry {attempt + 1}: {e}", file=sys.stderr)
            time.sleep(2 * (attempt + 1))


def parse_findings(raw: str) -> tuple[dict, bool]:
    """Parse the model's JSON; returns (data, truncated).

    If generation stopped at the token cap the JSON is cut mid-object. Rather than
    lose the whole file, salvage every complete finding object emitted before the
    cut and flag the result as truncated (recorded in the report's failures list
    as a note, so partial coverage is visible)."""
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    cleaned = re.sub(r"```[a-zA-Z]*\n?", "", raw).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(cleaned[start:end + 1]), False
        except json.JSONDecodeError:
            pass
    # Salvage: pull out complete {...} objects that look like findings.
    objs = []
    depth, buf = 0, ""
    arr = cleaned.find("[")
    for ch in cleaned[arr + 1:] if arr >= 0 else "":
        if ch == "{":
            depth += 1
        if depth > 0:
            buf += ch
        if ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    o = json.loads(buf)
                    if isinstance(o, dict) and "type" in o:
                        objs.append(o)
                except json.JSONDecodeError:
                    pass
                buf = ""
    if objs:
        return {"findings": objs}, True
    raise json.JSONDecodeError("unparseable and nothing to salvage", raw[:80], 0)


def iter_files(root: Path, exts: set) -> list:
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in exts:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        out.append(p)
    return out


def scan_file(path: Path, args) -> tuple[list, float, str | None]:
    code = path.read_text(encoding="utf-8", errors="replace")
    user_msg = USER_TMPL.format(types=ALLOWED_TYPES, filename=path.name,
                                numbered_code=number_lines(code))
    est_tokens = (len(user_msg) + len(SYSTEM)) // 4
    if est_tokens > args.max_prompt_tokens:
        return [], 0.0, f"skipped: ~{est_tokens} tokens > limit {args.max_prompt_tokens}"

    resp = call_api(args.base_url, args.api_key, args.model,
                    [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": user_msg}],
                    timeout=args.timeout, json_mode=not args.no_json_mode, max_tokens=args.max_output_tokens)
    usage = resp.get("usage", {}) or {}
    cost = price(args.model, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
    raw = resp["choices"][0]["message"]["content"] or ""
    data, truncated = parse_findings(raw)

    findings = []
    for f in data.get("findings", []) or []:
        try:
            line = int(f.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        try:
            conf = float(f.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        findings.append({
            "file": str(path.resolve()),
            "line": line,
            "type": str(f.get("type", "unknown")),
            "severity": str(f.get("severity", "medium")).lower(),
            "confidence": conf,
            "message": str(f.get("message", "")),
            "recommendation": "",
        })
    note = f"truncated output at token cap; salvaged {len(findings)} complete findings" if truncated else None
    return findings, cost, note


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-shot (no-pipeline) baseline")
    ap.add_argument("--bench-dir", required=True, help="directory to scan (recursively)")
    ap.add_argument("--lang", choices=sorted(LANG_EXT), default=None,
                    help="language to scan; default: infer from files present")
    ap.add_argument("--model", default=os.environ.get("DEEPGUARD_OPENAI_MODEL", "gpt-4o"))
    ap.add_argument("--base-url", default=os.environ.get("DEEPGUARD_OPENAI_BASE_URL", "https://api.openai.com/v1"))
    ap.add_argument("--output", default=None, help="report path (default: <bench-dir>/zero-shot-results.json)")
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("DEEPGUARD_REQUEST_TIMEOUT", "300")))
    ap.add_argument("--max-prompt-tokens", type=int, default=MAX_PROMPT_TOKENS_DEFAULT)
    ap.add_argument("--no-json-mode", action="store_true", help="don't request response_format=json_object")
    ap.add_argument("--max-output-tokens", type=int, default=4096)
    args = ap.parse_args()

    args.api_key = os.environ.get("DEEPGUARD_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
    if not args.api_key:
        print("ERROR: set DEEPGUARD_OPENAI_API_KEY (any non-empty value for local Ollama)", file=sys.stderr)
        return 1

    bench = Path(args.bench_dir).expanduser()
    if not bench.is_absolute():
        bench = REPO_ROOT / bench
    if not bench.is_dir():
        print(f"ERROR: not a directory: {bench}", file=sys.stderr)
        return 1

    if args.lang is None:
        args.lang = next((l for l, e in LANG_EXT.items() if iter_files(bench, e)), "js")
    files = iter_files(bench, LANG_EXT[args.lang])
    if not files:
        print(f"ERROR: no {args.lang} files under {bench}", file=sys.stderr)
        return 1

    out = Path(args.output).expanduser() if args.output else bench / "zero-shot-results.json"
    if not out.is_absolute():
        out = REPO_ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Zero-shot baseline — {len(files)} {args.lang} files, model={args.model} @ {args.base_url}")
    print("NO chunking · NO KB/RAG · NO framework hints · NO per-type templates\n")

    all_findings, total_cost, failures, started = [], 0.0, [], time.time()
    for path in files:
        rel = path.relative_to(bench)
        print(f"  {rel} ... ", end="", flush=True)
        try:
            findings, cost, note = scan_file(path, args)
        except Exception as e:  # noqa: BLE001 - record and continue
            failures.append({"file": str(rel), "error": str(e)[:200]})
            print(f"FAILED ({str(e)[:80]})")
            continue
        if note and not findings:
            failures.append({"file": str(rel), "error": note})
            print(note)
            continue
        if note:
            failures.append({"file": str(rel), "error": note, "partial": True})
            print(f"{len(findings)} findings ({note})")
        all_findings.extend(findings)
        total_cost += cost
        print(f"{len(findings)} findings")

    by_sev, by_type = {}, {}
    for f in all_findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    report = {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_path": str(bench),
            "languages": [args.lang],
            "model_used": args.model,
            "base_url": args.base_url,
            "mode": "zero_shot_no_pipeline",
            "total_cost": total_cost,
            "scan_duration_seconds": round(time.time() - started, 1),
            "files_scanned": len(files),
            # Same completeness contract as DeepGuard reports: a partial run must be visible.
            "analysis": {
                "attempted": len(files),
                "failed": len(failures),
                "complete": not failures,
                "failures": failures,
            },
        },
        "findings": all_findings,
        "summary": {"total_findings": len(all_findings), "by_severity": by_sev, "by_type": by_type},
    }
    out.write_text(json.dumps(report, indent=2))
    print(f"\nDone — {len(all_findings)} findings, {len(failures)} failed/skipped files, "
          f"cost ${total_cost:.4f}, {report['scan_metadata']['scan_duration_seconds']}s")
    print(f"Saved → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
