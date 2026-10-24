#!/usr/bin/env python3
"""
Stage 3 of the method, as an offline instrument: per-site judge and per-finding verifier.

Takes an existing DeepGuard run on RealVuln (scan-results/<repo>/<slug>/results.json),
groups findings into *sites* (same file, lines within --window), and for every site
where more than one vulnerability type was reported makes ONE model call that
selects which candidate(s) are real at that location. Optionally re-checks every
surviving finding cold ("verifier": fresh context, only the finding and the code).

Why offline: the sweep (stage 1) is the expensive part (~9 calls per function);
the judge needs only the flagged sites and the source, so it can be iterated on
cached sweeps without re-running them, and then ported into the Go pipeline.

Modes:
  judge    adjudicate contested sites only (default)
  verify   cold re-check of every finding, no adjudication
  both     judge, then verify what survives

Fail policy (--fail-policy): what to do when a model call errors or returns
unparseable output. keep = pass the candidates through untouched (protects
recall, default); drop = remove them (protects precision). Counted either way.

Usage:
  RV=~/Documents/university/Real-Vuln-Benchmark \\
  DEEPGUARD_OPENAI_BASE_URL=http://localhost:11434/v1 DEEPGUARD_OPENAI_API_KEY=ollama \\
  python3 scripts/realvuln_judge.py --slug deepguard-qwen7b --out-slug deepguard-qwen7b-judge \\
      --model qwen2.5-coder:7b [--mode judge|verify|both] [--repos r1 r2 ...]
Then: python3 scripts/realvuln_report.py deepguard-qwen7b-judge
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict

RV = os.environ.get("RV") or sys.exit("set RV to the Real-Vuln-Benchmark checkout")
# urllib's default User-Agent is rejected by Cloudflare in front of some providers
# (Groq returns 403 "error code: 1010"); identify the client explicitly.
USER_AGENT = "DeepGuard-research/0.1 (+https://github.com/nedaZarei/DeepGuard)"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

JUDGE_SYSTEM = (
    "You are a senior application-security reviewer adjudicating automated findings. "
    "Several scanners reported different vulnerability types at the same code location. "
    "Decide, from the code alone, which of the candidate reports describe a real, distinct "
    "vulnerability at that location. Usually one is right; sometimes none; rarely more than one. "
    "Respond ONLY with a JSON object."
)

JUDGE_USER = """\
Code ({file}, lines {lo}-{hi}; the reported location is around line {site}):
```
{excerpt}
```

Candidate reports for this location:
{candidates}

Rules:
- Judge from the code shown. Do not assume input is sanitised elsewhere unless the code shows it.
- Select a candidate only if the code at this location actually has that class of weakness.
- Two candidates that describe the same weakness under different names count as one: keep the more precise.
- Selecting none is a valid answer.

{selection_rule}

Return exactly:
{{"selected": {selected_shape}, "line": <integer line number that best evidences the selected weakness, or null>, "confidence": <0.0-1.0>, "reason": "<one sentence>"}}"""

SELECTION_RULES = {
    "multi": ("Select every candidate that is a real, distinct weakness at this location (usually one).",
              '["A", ...] or []'),
    "single": ("Select AT MOST ONE candidate: the one that most precisely names the weakness at this location. "
               "If two candidates describe the same problem, keep only the more precise one.",
               '["A"] or []'),
}
# --answer-format name: the model answers with the vulnerability type string instead of a
# letter, and must first state the weakness in its own words. Letters invite slips where
# the reason says "SQL query built from user input" but the selection is another row.
NAME_RULES = {
    "multi": ("First describe the weakness you see in one sentence. Then list every candidate TYPE NAME (exactly as "
              "written above) that is a real, distinct weakness at this location; usually one; an empty list if none."),
    "single": ("First describe the weakness you see in one sentence. Then give AT MOST ONE candidate TYPE NAME "
               "(exactly as written above) that most precisely names that weakness, or an empty list if none applies."),
}
JUDGE_USER_NAME = """\
Code ({file}, lines {lo}-{hi}; the reported location is around line {site}):
```
{excerpt}
```

Candidate types reported at this location (name: scanner's note):
{candidates}

Rules:
- Judge from the code shown. Do not assume input is sanitised elsewhere unless the code shows it.
- A type is correct only if the code at this location actually has that class of weakness.
- Two names for the same weakness count as one: keep the more precise.
- Selecting none is a valid answer.

{selection_rule}

Return exactly:
{{"weakness": "<one sentence>", "selected_types": ["<type name>", ...] or [], "line": <integer line number that best evidences it, or null>, "confidence": <0.0-1.0>}}"""

VERIFY_SYSTEM = (
    "You are a senior application-security reviewer. A scanner reported one vulnerability at one "
    "code location. Decide from the code alone whether that report is correct. "
    "Respond ONLY with a JSON object."
)

VERIFY_USER = """\
Code ({file}, lines {lo}-{hi}):
```
{excerpt}
```

Reported finding: {vtype} at line {line}. Scanner's note: {message}

Is this a real {vtype} vulnerability at this location? Do not assume sanitisation that the code does not show.
Return exactly: {{"applies": true or false, "confidence": <0.0-1.0>, "reason": "<one sentence>"}}"""


# Verifier that must state a concrete failure before ruling. Asking for the evidence
# fields before the verdict is the same ordering that fixed the judge (7.22).
VERIFY_ATTACK_USER = """\
Code ({file}, lines {lo}-{hi}):
```
{excerpt}
```
{xref}
Reported finding: {vtype} at line {line}. Scanner's note: {message}

A report is correct only if the code shown supports a concrete failure, not just a risky-looking pattern.
For injection-style weaknesses, name what an attacker controls, how it reaches the dangerous operation
at this location, and why nothing shown prevents it. For authentication or cryptography weaknesses, name
the protected operation or secret and the missing or weak control. If you cannot state this from the
code shown, the report does not apply. Do not assume sanitisation the code does not show.

Return exactly:
{{"attacker_input": "<what the attacker controls, or none>", "dangerous_operation": "<the operation at this location>", "why_not_prevented": "<one sentence>", "applies": true or false, "confidence": <0.0-1.0>}}"""

_last_call = [0.0]


def call(base_url: str, api_key: str, model: str, system: str, user: str, timeout: int, interval: float = 0.0) -> dict:
    if interval > 0:
        wait = _last_call[0] + interval - time.time()
        if wait > 0:
            time.sleep(wait)
    _last_call[0] = time.time()
    payload = {"model": model, "temperature": 0,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
               "response_format": {"type": "json_object"}}
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}", "User-Agent": USER_AGENT},
                                 method="POST")
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
            raw = body["choices"][0]["message"]["content"] or ""
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                cleaned = re.sub(r"```[a-zA-Z]*\n?", "", raw)
                s, e = cleaned.find("{"), cleaned.rfind("}")
                return json.loads(cleaned[s:e + 1])
        except Exception as ex:  # noqa: BLE001
            last = ex
            time.sleep(20 * (attempt + 1) if "429" in str(ex) else 2 * (attempt + 1))
    raise RuntimeError(f"model call failed: {last}")


def parse_line(v) -> int | None:
    """Accept 14, "14", "14: code", "line 14"; reject anything else."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        m = re.search(r"\d+", v)
        if m:
            return int(m.group())
    return None


def read_lines(repo: str, rel: str) -> list[str] | None:
    p = os.path.join(RV, "repos", repo, rel)
    try:
        return open(p, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return None


def excerpt(lines: list[str], center: int, ctx: int) -> tuple[int, int, str]:
    lo, hi = max(1, center - ctx), min(len(lines), center + ctx)
    w = len(str(hi))
    return lo, hi, "\n".join(f"{i:{w}d}: {lines[i - 1]}" for i in range(lo, hi + 1))


_DEF = {
    ".py": r"^\s*(?:async\s+)?def\s+{name}\s*\(",
    ".js": r"(?:function\s+{name}\s*\(|\b{name}\s*[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))",
}
_DEF[".ts"] = _DEF[".js"]
_CALL = r"\b{name}\s*\("
# Web handlers are invoked by the framework, so their real "caller" is the route
# registration (Express router.get('/x', mw, handler); Django path('x', views.handler)).
_ROUTE = r"(?:\.(?:get|post|put|patch|delete|all|use|route)\s*\(|\b(?:path|re_path|url)\s*\().*\b{name}\b"
_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
_SKIP_EXT = {".git", "node_modules", "venv", ".venv", "site-packages", "migrations", "__pycache__", "dist", "build"}


def _repo_files(repo: str, ext: str) -> list[str]:
    root = os.path.join(RV, "repos", repo)
    out = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP_EXT]
        out.extend(os.path.join(dp, f) for f in fns if f.endswith(ext))
    return out


def _enclosing_function(lines: list[str], line: int, ext: str) -> str | None:
    pat = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(" if ext == ".py"
                     else r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(|\b([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function\b|\())")
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = pat.search(lines[i])
        if m:
            return next(g for g in m.groups() if g)
    return None


def xref_context(repo: str, rel: str, lines: list[str], line: int, lo: int, hi: int, budget: int = 2400) -> str:
    """Name-based callers of the enclosing function and definitions of functions it calls.

    An approximation of a call graph (no type resolution): enough to show where a
    parameter comes from or what a helper does, which a single excerpt cannot.
    """
    ext = os.path.splitext(rel)[1]
    if ext not in _DEF:
        return ""
    files = _repo_files(repo, ext)
    root = os.path.join(RV, "repos", repo)
    parts = []

    fn = _enclosing_function(lines, line, ext)
    if fn and fn not in ("__init__", "main"):
        call = re.compile(_CALL.format(name=re.escape(fn)) + "|" + _ROUTE.format(name=re.escape(fn)))
        defn = re.compile(_DEF[ext].format(name=re.escape(fn)))
        shown = 0
        for path in files:
            try:
                fl = open(path, encoding="utf-8", errors="replace").read().split("\n")
            except OSError:
                continue
            for i, l in enumerate(fl):
                if call.search(l) and not defn.search(l):
                    r0 = os.path.relpath(path, root)
                    if r0 == rel and lo <= i + 1 <= hi:
                        continue
                    a, b = max(0, i - 3), min(len(fl), i + 2)
                    parts.append(f"Caller of {fn} ({r0}, lines {a + 1}-{b}):\n" + "\n".join(f"{j + 1}: {fl[j]}" for j in range(a, b)))
                    shown += 1
                    break
            if shown >= 2:
                break

    callees = []
    for l in lines[lo - 1:hi]:
        callees.extend(m.group(1) for m in _IDENT.finditer(l))
    seen = set()
    for name in callees:
        if name in seen or name == fn or len(parts) >= 4:
            continue
        seen.add(name)
        defn = re.compile(_DEF[ext].format(name=re.escape(name)))
        for path in files:
            try:
                fl = open(path, encoding="utf-8", errors="replace").read().split("\n")
            except OSError:
                continue
            hit = next((i for i, l in enumerate(fl) if defn.search(l)), None)
            if hit is not None:
                r0 = os.path.relpath(path, root)
                if r0 == rel and lo <= hit + 1 <= hi:
                    break
                b = min(len(fl), hit + 10)
                parts.append(f"Definition of {name} ({r0}, lines {hit + 1}-{b}):\n" + "\n".join(f"{j + 1}: {fl[j]}" for j in range(hit, b)))
                break

    text = ""
    for p_ in parts:
        if len(text) + len(p_) > budget:
            break
        text += "\n" + p_ + "\n"
    return f"\nRelated code elsewhere in the repository:\n```{text}```\n" if text else ""


def group_sites(results: list[dict], window: int) -> list[list[dict]]:
    """Cluster findings by file and line proximity (single-linkage within `window`)."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_file[r["path"]].append(r)
    sites = []
    for path, rs in by_file.items():
        rs.sort(key=lambda r: r["start"]["line"])
        cur = [rs[0]]
        for r in rs[1:]:
            if r["start"]["line"] - cur[-1]["start"]["line"] <= window:
                cur.append(r)
            else:
                sites.append(cur)
                cur = [r]
        sites.append(cur)
    return sites


def vtype(r: dict) -> str:
    return r["extra"]["metadata"].get("deepguard_type") or r["check_id"].split(".")[-1]


def judge_site(site: list[dict], repo: str, args, stats: Counter, log: list) -> list[dict]:
    types = sorted({vtype(r) for r in site})
    if len(types) < 2:
        stats["sites_uncontested"] += 1
        return site
    stats["sites_contested"] += 1
    lines = read_lines(repo, site[0]["path"])
    if lines is None:
        stats["file_unreadable"] += 1
        return site
    center = round(sum(r["start"]["line"] for r in site) / len(site))
    lo, hi, exc = excerpt(lines, center, args.context)

    # One candidate per type: keep the highest-confidence report of each type.
    best: dict[str, dict] = {}
    for r in site:
        t = vtype(r)
        if t not in best or (r["extra"]["metadata"].get("confidence") or 0) > (best[t]["extra"]["metadata"].get("confidence") or 0):
            best[t] = r
    letters = [chr(ord("A") + i) for i in range(len(best))]
    cand_lines, by_letter = [], {}
    for letter, (t, r) in zip(letters, sorted(best.items())):
        by_letter[letter] = r
        cand_lines.append(f"{letter}. {t} (reported at line {r['start']['line']}, "
                          f"confidence {r['extra']['metadata'].get('confidence', '?')}): {r['extra'].get('message', '')[:200]}")
    if args.answer_format == "name":
        name_lines = [f"- {t}: {r['extra'].get('message', '')[:200]}" for t, r in sorted(best.items())]
        user = JUDGE_USER_NAME.format(file=site[0]["path"], lo=lo, hi=hi, site=center, excerpt=exc,
                                      candidates="\n".join(name_lines), selection_rule=NAME_RULES[args.select_mode])
    else:
        rule, shape = SELECTION_RULES[args.select_mode]
        user = JUDGE_USER.format(file=site[0]["path"], lo=lo, hi=hi, site=center, excerpt=exc,
                                 candidates="\n".join(cand_lines), selection_rule=rule, selected_shape=shape)
    entry = {"repo": repo, "file": site[0]["path"], "site": center, "candidates": {l: vtype(r) for l, r in by_letter.items()}}
    try:
        out = call(args.base_url, args.api_key, args.model, JUDGE_SYSTEM, user, args.timeout, args.interval)
        stats["judge_calls"] += 1
        if args.answer_format == "name":
            by_name = {t: l for l, t in ((l, vtype(r)) for l, r in by_letter.items())}
            raw_sel = out.get("selected_types") or out.get("selected") or []
            sel = sorted({by_name[s.strip()] for s in raw_sel if isinstance(s, str) and s.strip() in by_name})
            if raw_sel and not sel:
                stats["name_not_a_candidate"] += 1
            entry["weakness"] = out.get("weakness")
        else:
            sel = [s for s in (out.get("selected") or []) if isinstance(s, str) and s.strip().upper()[:1] in by_letter]
            sel = sorted({s.strip().upper()[:1] for s in sel})
        if args.select_mode == "single" and len(sel) > 1:
            stats["single_mode_truncated"] += 1
            sel = sel[:1]
        entry.update({"selected": sel, "line": out.get("line"), "confidence": out.get("confidence"), "reason": out.get("reason")})
        log.append(entry)
        stats[f"selected_{min(len(sel), 2)}{'plus' if len(sel) >= 2 else ''}"] += 1
        kept = []
        for letter in sel:
            r = dict(by_letter[letter])
            r["extra"] = dict(r["extra"]); r["extra"]["metadata"] = dict(r["extra"]["metadata"])
            r["extra"]["metadata"]["judge"] = {"site": center, "n_candidates": len(by_letter), "reason": out.get("reason")}
            jl = parse_line(out.get("line"))
            if jl is not None and lo <= jl <= hi and abs(jl - r["start"]["line"]) <= args.window * 2:
                r["start"] = {"line": jl, "col": 1}; r["end"] = {"line": jl, "col": 1}
            kept.append(r)
        stats["findings_in_contested"] += len(site)
        stats["findings_kept_by_judge"] += len(kept)
        return kept
    except Exception as ex:  # noqa: BLE001
        stats["judge_errors"] += 1
        entry.update({"error": str(ex)[:160]})
        log.append(entry)
        if args.fail_policy == "drop":
            stats["dropped_on_error"] += len(site)
            return []
        return site


def verify_finding(r: dict, repo: str, args, stats: Counter, log: list) -> dict | None:
    lines = read_lines(repo, r["path"])
    if lines is None:
        stats["file_unreadable"] += 1
        return r
    lo, hi, exc = excerpt(lines, r["start"]["line"], args.context)
    xref = xref_context(repo, r["path"], lines, r["start"]["line"], lo, hi) if args.xref else ""
    if args.verify_prompt == "attack":
        user = VERIFY_ATTACK_USER.format(file=r["path"], lo=lo, hi=hi, excerpt=exc, xref=xref, vtype=vtype(r),
                                         line=r["start"]["line"], message=(r["extra"].get("message") or "")[:200])
    else:
        user = VERIFY_USER.format(file=r["path"], lo=lo, hi=hi, excerpt=exc + (("\n```\n" + xref + "```") if xref else ""),
                                  vtype=vtype(r), line=r["start"]["line"], message=(r["extra"].get("message") or "")[:200])
    entry = {"repo": repo, "file": r["path"], "line": r["start"]["line"], "type": vtype(r), "xref_chars": len(xref)}
    try:
        out = call(args.base_url, args.api_key, args.model, VERIFY_SYSTEM, user, args.timeout, args.interval)
        stats["verify_calls"] += 1
        applies = bool(out.get("applies"))
        entry.update({"applies": applies, "confidence": out.get("confidence"),
                      "reason": out.get("reason") or out.get("why_not_prevented"),
                      "attacker_input": out.get("attacker_input"), "dangerous_operation": out.get("dangerous_operation")})
        log.append(entry)
        if not applies:
            stats["verify_rejected"] += 1
            return None
        stats["verify_confirmed"] += 1
        r = dict(r); r["extra"] = dict(r["extra"]); r["extra"]["metadata"] = dict(r["extra"]["metadata"])
        r["extra"]["metadata"]["verify"] = {"confidence": out.get("confidence"), "reason": out.get("reason")}
        return r
    except Exception as ex:  # noqa: BLE001
        stats["verify_errors"] += 1
        entry.update({"error": str(ex)[:160]})
        log.append(entry)
        return None if args.fail_policy == "drop" else r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True, help="existing run to post-process")
    ap.add_argument("--out-slug", required=True)
    ap.add_argument("--mode", choices=["judge", "verify", "both"], default="judge")
    ap.add_argument("--model", default=os.environ.get("DEEPGUARD_OPENAI_MODEL", "qwen2.5-coder:7b"))
    ap.add_argument("--base-url", default=os.environ.get("DEEPGUARD_OPENAI_BASE_URL", "http://localhost:11434/v1"))
    ap.add_argument("--window", type=int, default=3, help="lines: findings this close form one site")
    ap.add_argument("--context", type=int, default=15, help="lines of code shown on each side of a site")
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("DEEPGUARD_REQUEST_TIMEOUT", "300")))
    ap.add_argument("--fail-policy", choices=["keep", "drop"], default="keep")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("DEEPGUARD_MIN_REQUEST_INTERVAL_MS", "0")) / 1000,
                    help="seconds to wait between model calls (rate-limited free tiers)")
    ap.add_argument("--answer-format", choices=["letter", "name"], default="letter",
                    help="name: model answers with the type string after stating the weakness (see NAME_RULES)")
    ap.add_argument("--select-mode", choices=["multi", "single"], default="single",
                    help="single: at most one type per site (default); multi: any number")
    ap.add_argument("--verify-prompt", choices=["basic", "attack"], default="basic",
                    help="attack: the verifier must state a concrete failure before ruling")
    ap.add_argument("--xref", action="store_true", help="give the verifier name-based callers and callees")
    ap.add_argument("--repos", nargs="*", default=None)
    args = ap.parse_args()
    args.api_key = os.environ.get("DEEPGUARD_OPENAI_API_KEY", "ollama")

    repos = args.repos or sorted(p.split("/")[-3] for p in glob.glob(f"{RV}/scan-results/realvuln-*/{args.slug}/results.json"))
    if not repos:
        sys.exit(f"no results for {args.slug}")

    log_dir = os.path.join(ROOT, "reports", "realvuln-judge", args.out_slug)
    os.makedirs(log_dir, exist_ok=True)
    total = Counter()
    started = time.time()
    for repo in repos:
        src = f"{RV}/scan-results/{repo}/{args.slug}/results.json"
        dst_dir = f"{RV}/scan-results/{repo}/{args.out_slug}"
        if os.path.exists(f"{dst_dir}/results.json"):
            print(f"=== {repo} === (done, skipping)")
            continue
        data = json.load(open(src))
        results = data.get("results", [])
        stats, log = Counter(), []
        stats["findings_in"] = len(results)
        print(f"=== {repo} === {len(results)} findings", flush=True)

        kept = results
        if args.mode in ("judge", "both"):
            kept = []
            for site in group_sites(results, args.window):
                kept.extend(judge_site(site, repo, args, stats, log))
        if args.mode in ("verify", "both"):
            kept = [v for v in (verify_finding(r, repo, args, stats, log) for r in kept) if v is not None]
        stats["findings_out"] = len(kept)

        os.makedirs(dst_dir, exist_ok=True)
        json.dump({"results": kept, "errors": [], "version": f"{args.out_slug}"}, open(f"{dst_dir}/results.json", "w"), indent=2)
        json.dump({"repo": repo, "mode": args.mode, "model": args.model, "stats": dict(stats), "decisions": log},
                  open(os.path.join(log_dir, f"{repo}.json"), "w"), indent=2)
        total.update(stats)
        print("   " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())), flush=True)

    summary = {"slug_in": args.slug, "slug_out": args.out_slug, "mode": args.mode, "select_mode": args.select_mode, "answer_format": args.answer_format,
               "verify_prompt": args.verify_prompt, "xref": args.xref, "model": args.model,
               "window": args.window, "context": args.context, "fail_policy": args.fail_policy,
               "repos": repos, "wall_seconds": round(time.time() - started), "stats": dict(total)}
    errors = total.get("judge_errors", 0) + total.get("verify_errors", 0)
    summary["incomplete"] = errors > 0
    json.dump(summary, open(os.path.join(log_dir, "_summary.json"), "w"), indent=2)
    print("\nTOTAL " + ", ".join(f"{k}={v}" for k, v in sorted(total.items())))
    print(f"logs: {log_dir}\nscore with: RV={RV} python3 scripts/realvuln_report.py {args.out_slug}")
    if errors:
        # A run with failed calls is not a measurement: under the keep policy the affected
        # findings passed through untouched. Mark it so scoring scripts refuse it by default.
        marker = os.path.join(log_dir, "INCOMPLETE")
        open(marker, "w").write(f"{errors} failed model calls; re-run before scoring\n")
        print(f"\nWARNING: {errors} model calls failed -> results are PARTIAL. Marker written: {marker}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
