#!/usr/bin/env python3
"""
CodeXGLUE C/C++ Defect Detection Evaluation for Deep-Guard.

Evaluates Deep-Guard's C/C++ vulnerability detection on the Devign dataset
(CodeXGLUE Defect Detection track). The dataset contains C functions labelled
1 (defective) or 0 (clean).

Dataset source (JSONL, one function per line):
  https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection

Usage:
    # Download dataset first:
    #   wget https://raw.githubusercontent.com/microsoft/CodeXGLUE/main/
    #         Code-Code/Defect-detection/dataset/test.jsonl

    python3 scripts/codexglue_evaluation.py \\
        --dataset dataset/test.jsonl \\
        --sample 100 \\
        --output reports/codexglue-results.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

# ─── Configuration ──────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).parent.parent
BINARY    = REPO_ROOT / "deepguard"
API_KEY   = os.environ.get("DEEPGUARD_OPENAI_API_KEY", "")
BASE_URL  = os.environ.get("DEEPGUARD_OPENAI_BASE_URL", "https://api.gapgpt.app/v1")

C_VULN_TYPES = ["buffer_overflow", "format_string", "use_after_free", "integer_overflow"]

# ─── Helpers ─────────────────────────────────────────────────────────────────


def scan_c_function(func_code: str, func_name: str) -> Optional[bool]:
    """
    Write the C function to a temp file and scan it with deepguard.
    Returns True (defective detected), False (clean), or None (scan error).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / f"{func_name}.c"
        # Wrap bare function in minimal C to satisfy the compiler
        src.write_text(f"#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n{func_code}\n")

        out_dir = Path(tmpdir) / "out"
        out_dir.mkdir()

        env = {**os.environ,
               "DEEPGUARD_OPENAI_API_KEY": API_KEY,
               "DEEPGUARD_OPENAI_BASE_URL": BASE_URL}

        cmd = [str(BINARY), "scan", "--path", str(tmpdir), "--output", str(out_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)

        if result.returncode != 0:
            return None

        # Check if any finding was emitted
        for f in out_dir.glob("scan-*.json"):
            try:
                data = json.loads(f.read_text())
                findings = data.get("findings", [])
                # A positive prediction: any C-type finding present
                for finding in findings:
                    if finding.get("type") in C_VULN_TYPES:
                        return True
                return False
            except Exception:
                return None
    return None


def load_dataset(path: str, sample: int) -> list[dict]:
    samples = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                samples.append(obj)
            except json.JSONDecodeError:
                continue
            if sample and len(samples) >= sample:
                break
    return samples


def evaluate(dataset_path: str, sample: int, output_path: Optional[str]) -> dict:
    print(f"Loading dataset from {dataset_path} (max {sample} samples)...")
    samples = load_dataset(dataset_path, sample)
    print(f"  Loaded {len(samples)} samples\n")

    tp = fp = tn = fn = 0
    errors = 0
    per_sample = []

    for i, s in enumerate(samples):
        label   = int(s.get("target", s.get("label", 0)))  # 1=defective, 0=clean
        code    = s.get("func", s.get("code", ""))
        idx     = s.get("idx", i)

        print(f"  [{i+1:>4}/{len(samples)}] idx={idx} label={label} ", end="", flush=True)
        pred = scan_c_function(code, f"fn_{idx}")

        if pred is None:
            errors += 1
            status = "ERROR"
        elif pred and label == 1:
            tp += 1; status = "TP"
        elif pred and label == 0:
            fp += 1; status = "FP"
        elif not pred and label == 0:
            tn += 1; status = "TN"
        else:
            fn += 1; status = "FN"
        print(status)

        per_sample.append({"idx": idx, "label": label, "predicted": pred, "status": status})

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy  = (tp + tn) / total if total else 0.0

    results = {
        "dataset":    dataset_path,
        "samples":    len(samples),
        "evaluable":  total,
        "errors":     errors,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision":  round(precision, 4),
        "recall":     round(recall, 4),
        "f1":         round(f1, 4),
        "accuracy":   round(accuracy, 4),
        "per_sample": per_sample,
    }

    _print_summary(results)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {output_path}")

    return results


def _print_summary(r: dict) -> None:
    print(f"""
═══ CodeXGLUE Defect Detection ════════════════════════════════
  Dataset:   {r['dataset']}
  Samples:   {r['samples']}  (evaluable: {r['evaluable']}, errors: {r['errors']})

  Confusion matrix:
    TP={r['TP']}  FP={r['FP']}
    FN={r['FN']}  TN={r['TN']}

  Precision : {r['precision']:.4f}
  Recall    : {r['recall']:.4f}
  F1        : {r['f1']:.4f}
  Accuracy  : {r['accuracy']:.4f}
═══════════════════════════════════════════════════════════════
""")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Evaluate Deep-Guard on CodeXGLUE C/C++ defect dataset")
    p.add_argument("--dataset", required=True, help="Path to test.jsonl from Devign/CodeXGLUE")
    p.add_argument("--sample",  type=int, default=200,
                   help="Number of samples to evaluate (default: 200; 0 = all)")
    p.add_argument("--output",  default="reports/codexglue-results.json",
                   help="Output JSON path")
    args = p.parse_args()

    if not API_KEY:
        print("ERROR: DEEPGUARD_OPENAI_API_KEY not set", file=sys.stderr)
        sys.exit(1)
    if not BINARY.exists():
        print(f"ERROR: deepguard binary not found at {BINARY}", file=sys.stderr)
        sys.exit(1)
    if not Path(args.dataset).exists():
        print(f"ERROR: dataset not found: {args.dataset}", file=sys.stderr)
        print("Download from:")
        print("  https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection")
        sys.exit(1)

    evaluate(args.dataset, args.sample, args.output)


if __name__ == "__main__":
    main()
