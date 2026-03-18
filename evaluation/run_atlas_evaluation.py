#!/usr/bin/env python3
"""
AIProbe MITRE ATLAS Benchmark Evaluation
=========================================
Evaluates AIProbe's Agent Scanner against independently developed vulnerable
agent scripts mapped to MITRE ATLAS (Adversarial Threat Landscape for AI
Systems) technique categories.

Each benchmark agent is constructed with specific, known vulnerability
patterns corresponding to one or more ATLAS techniques.  Ground-truth
labels are defined per file so that detection rates, false-negative rates,
and false-positive rates can be computed automatically.

Usage:
    python run_atlas_evaluation.py
"""

import sys
import os
import time
import json
import io
from pathlib import Path
from collections import defaultdict

# Fix encoding for Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def _long_path(p: Path) -> Path:
    """Return a Windows extended-length path to bypass the 260-char MAX_PATH limit."""
    s = str(p.resolve())
    if sys.platform == "win32" and not s.startswith("\\\\?\\"):
        s = "\\\\?\\" + s
    return Path(s)

# Add parent dir so we can import ai_cybersecurity
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_cybersecurity import AgentScanner, MLScanner
from ai_cybersecurity.utils import VulnerabilityLevel

# ---------------------------------------------------------------------------
# Ground-truth definitions
# ---------------------------------------------------------------------------
# Each entry maps a benchmark file to:
#   atlas_id    – MITRE ATLAS technique identifier
#   atlas_name  – human-readable technique name
#   expected_vuln_titles – set of vulnerability title sub-strings that SHOULD
#                          be detected (case-insensitive partial match)
#   is_clean    – True for benign files used to measure false positives

AGENT_BENCHMARKS = [
    {
        "file": "benchmark_agents/atlas_prompt_injection.py",
        "atlas_id": "AML.T0051",
        "atlas_name": "LLM Prompt Injection",
        "expected_vuln_titles": [
            "prompt injection",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": "benchmark_agents/atlas_unsafe_code_exec.py",
        "atlas_id": "AML.T0048",
        "atlas_name": "Command and Scripting — Unsafe Code Execution",
        "expected_vuln_titles": [
            "unsafe code execution",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": "benchmark_agents/atlas_goal_hijacking.py",
        "atlas_id": "AML.T0054",
        "atlas_name": "LLM Goal Hijacking / Goal Manipulation",
        "expected_vuln_titles": [
            "goal manipulation",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": "benchmark_agents/atlas_supply_chain.py",
        "atlas_id": "AML.T0010",
        "atlas_name": "ML Supply Chain Compromise",
        "expected_vuln_titles": [
            "supply chain",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": "benchmark_agents/atlas_no_auth.py",
        "atlas_id": "AML.T0040",
        "atlas_name": "ML Model Access — Missing Authorization",
        "expected_vuln_titles": [
            "authorization",
            "identity",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": "benchmark_agents/atlas_inter_agent_comms.py",
        "atlas_id": "AML.T0049",
        "atlas_name": "Insecure Inter-Agent Communication",
        "expected_vuln_titles": [
            "communication",
            "unsafe code execution",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    # ---------- clean (benign) file for false-positive measurement ----------
    {
        "file": "benchmark_agents/clean_agent.py",
        "atlas_id": "N/A",
        "atlas_name": "Benign Agent (FP Baseline)",
        "expected_vuln_titles": [],
        "min_expected": 0,
        "is_clean": True,
    },
]

# ML model benchmarks use files already in the repository
# Resolve the workspace root (two levels up from Code/ai_cybersecurity-main Github/evaluation)
_WS_ROOT = Path(__file__).resolve().parent.parent.parent.parent

ML_BENCHMARKS = [
    {
        "file": str(_WS_ROOT / "plateform" / "malicious_model.pkl"),
        "atlas_id": "AML.T0010",
        "atlas_name": "ML Supply Chain — Insecure Serialization",
        "expected_vuln_titles": [
            "insecure serialization",
            "malicious payload",
        ],
        "min_expected": 1,
        "is_clean": False,
    },
    {
        "file": str(_WS_ROOT / "plateform" / "my_classifier.pkl"),
        "atlas_id": "AML.T0010",
        "atlas_name": "ML Supply Chain — Pickle Model",
        "expected_vuln_titles": [
            "insecure serialization",
        ],
        "min_expected": 1,
        "is_clean": False,  # Pickle is inherently insecure serialization
    },
    {
        "file": str(_WS_ROOT / "plateform" / "my_classifier.joblib"),
        "atlas_id": "AML.T0010",
        "atlas_name": "ML Supply Chain — Joblib Model",
        "expected_vuln_titles": [
            "insecure serialization",
        ],
        "min_expected": 1,
        "is_clean": False,  # Joblib is also insecure serialization
    },
    {
        "file": str(Path(__file__).resolve().parent / "benchmark_models" / "benign_model.json"),
        "atlas_id": "N/A",
        "atlas_name": "Benign JSON Model (FP Baseline)",
        "expected_vuln_titles": [],
        "min_expected": 0,
        "is_clean": True,
    },
]


def match_vuln(vuln_title: str, expected_patterns: list) -> bool:
    """Check if a vulnerability title matches any expected pattern."""
    title_lower = vuln_title.lower()
    return any(pat.lower() in title_lower for pat in expected_patterns)


def run_evaluation():
    eval_dir = _long_path(Path(__file__).resolve().parent)
    agent_scanner = AgentScanner()
    ml_scanner = MLScanner()

    results = []

    print("=" * 80)
    print("AIProbe -- MITRE ATLAS Benchmark Evaluation")
    print("=" * 80)

    # ---- Agent benchmarks ----
    print("\n--- Agent Scanner Benchmarks ---\n")
    for bench in AGENT_BENCHMARKS:
        filepath = _long_path(eval_dir / bench["file"])
        if not filepath.exists():
            print(f"  [SKIP] {bench['file']} -- file not found")
            continue

        t0 = time.time()
        try:
            vulns = agent_scanner.scan_agent(filepath)
        except Exception as e:
            print(f"  [ERROR] {bench['file']}: {e}")
            vulns = []
        elapsed = time.time() - t0

        # Classify detections
        vuln_titles = [v.title for v in vulns]
        true_positives = sum(1 for v in vulns if match_vuln(v.title, bench["expected_vuln_titles"])) if bench["expected_vuln_titles"] else 0
        total_detected = len(vulns)
        false_positives = total_detected - true_positives if not bench["is_clean"] else total_detected

        detected = true_positives >= bench["min_expected"]

        severity_counts = defaultdict(int)
        for v in vulns:
            severity_counts[v.level.value] += 1

        entry = {
            "file": bench["file"],
            "atlas_id": bench["atlas_id"],
            "atlas_name": bench["atlas_name"],
            "scan_type": "Agent",
            "is_clean": bench["is_clean"],
            "total_vulns": total_detected,
            "true_positives": true_positives,
            "false_positives": false_positives if not bench["is_clean"] else total_detected,
            "detected": detected,
            "elapsed_s": round(elapsed, 2),
            "severity": dict(severity_counts),
            "vuln_titles": vuln_titles,
        }
        results.append(entry)

        status = "[OK] DETECTED" if detected else ("[FP] FP-CHECK" if bench["is_clean"] else "[!!] MISSED")
        print(f"  {status} | {bench['atlas_id']:12s} | {bench['atlas_name'][:45]:45s} | Vulns={total_detected:2d} | TP={true_positives} | {elapsed:.2f}s")

    # ---- ML model benchmarks ----
    print("\n--- ML Scanner Benchmarks ---\n")
    for bench in ML_BENCHMARKS:
        filepath = _long_path(Path(bench["file"]))
        if not filepath.exists():
            print(f"  [SKIP] {Path(bench['file']).name} -- file not found")
            continue

        t0 = time.time()
        try:
            vulns = ml_scanner.scan_model(filepath)
        except Exception as e:
            print(f"  [ERROR] {bench['file']}: {e}")
            vulns = []
        elapsed = time.time() - t0

        vuln_titles = [v.title for v in vulns]
        true_positives = sum(1 for v in vulns if match_vuln(v.title, bench["expected_vuln_titles"])) if bench["expected_vuln_titles"] else 0
        total_detected = len(vulns)
        false_positives = total_detected - true_positives if not bench["is_clean"] else total_detected

        detected = true_positives >= bench["min_expected"]

        severity_counts = defaultdict(int)
        for v in vulns:
            severity_counts[v.level.value] += 1

        entry = {
            "file": bench["file"],
            "atlas_id": bench["atlas_id"],
            "atlas_name": bench["atlas_name"],
            "scan_type": "ML",
            "is_clean": bench["is_clean"],
            "total_vulns": total_detected,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "detected": detected,
            "elapsed_s": round(elapsed, 2),
            "severity": dict(severity_counts),
            "vuln_titles": vuln_titles,
        }
        results.append(entry)

        status = "[OK] DETECTED" if detected else "[!!] MISSED"
        print(f"  {status} | {bench['atlas_id']:12s} | {bench['atlas_name'][:45]:45s} | Vulns={total_detected:2d} | TP={true_positives} | {elapsed:.2f}s")

    # ---- Summary statistics ----
    vuln_benchmarks = [r for r in results if not r["is_clean"]]
    clean_benchmarks = [r for r in results if r["is_clean"]]

    total_vuln = len(vuln_benchmarks)
    total_detected = sum(1 for r in vuln_benchmarks if r["detected"])
    detection_rate = (total_detected / total_vuln * 100) if total_vuln else 0

    total_fp = sum(r["false_positives"] for r in clean_benchmarks)
    total_clean_vulns = sum(r["total_vulns"] for r in clean_benchmarks)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"  Vulnerable benchmarks: {total_vuln}")
    print(f"  Correctly detected:    {total_detected} / {total_vuln}  ({detection_rate:.1f}%)")
    print(f"  Clean benchmarks:      {len(clean_benchmarks)}")
    print(f"  False positives (clean): {total_fp} finding(s) across {len(clean_benchmarks)} clean file(s)")
    print()

    # ---- Save JSON results ----
    output_path = _long_path(eval_dir / "atlas_evaluation_results.json")
    with open(str(output_path), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"  Results saved to: {output_path}")

    return results


if __name__ == "__main__":
    run_evaluation()
