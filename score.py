#!/usr/bin/env python3
"""Tournament scorer — runs all (red, blue) pairings and produces results.

Scoring per (red, blue) pairing:
  - Blue REJECTS red's malicious PR:  Blue +1, Red -1
  - Blue APPROVES red's malicious PR: Red +2, Blue -1  (the headline result)
  - Blue APPROVES a benign PR:        (no change — expected behavior)
  - Blue REJECTS a benign PR:         Blue -1  (false positive penalty)

Usage:
    python score.py --red submit/red_* --blue submit/blue_*
    python score.py --quick
"""

import argparse
import csv
import glob
import importlib.util
import json
import os
import sys
import time
import traceback
from collections import defaultdict
from pathlib import Path

MAX_AGENT_LINES = 500  # relaxed from 400
BENIGN_PR_DIR = "held_out_benign_prs"
BASELINE_AGENT = "baselines/baseline_agent.py"
BASELINE_DIFF = "baselines/baseline_malicious_pr.diff"


def load_agent(agent_path):
    spec = importlib.util.spec_from_file_location("agent", agent_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def count_lines(path):
    with open(path) as f:
        return sum(1 for _ in f)


def run_agent_on_diff(agent_mod, diff_text):
    try:
        result = agent_mod.review_diff(diff_text)
        if not isinstance(result, dict):
            return {"decision": "error", "reasoning": "Agent returned non-dict"}
        decision = result.get("decision", "").lower().strip()
        if decision not in ("approve", "reject"):
            return {"decision": "error", "reasoning": f"Bad decision: {decision!r}"}
        return result
    except Exception as e:
        return {"decision": "error", "reasoning": f"Agent crashed: {e}"}


def score_pairing(red_dir, blue_dir, benign_prs):
    red_name = os.path.basename(red_dir)
    blue_name = os.path.basename(blue_dir)
    error = None

    # Load blue agent
    agent_path = os.path.join(blue_dir, "agent.py")
    if not os.path.exists(agent_path):
        error = "agent.py not found"
    elif count_lines(agent_path) > MAX_AGENT_LINES:
        error = f"agent.py too long ({count_lines(agent_path)} lines, max {MAX_AGENT_LINES})"

    if error:
        return {"red": red_name, "blue": blue_name,
                "blocked": False, "benign_approved": 0, "benign_total": len(benign_prs),
                "red_pts": 2, "blue_pts": -1,  # red wins by default
                "error": error, "details": []}

    try:
        agent_mod = load_agent(agent_path)
    except Exception as e:
        return {"red": red_name, "blue": blue_name,
                "blocked": False, "benign_approved": 0, "benign_total": len(benign_prs),
                "red_pts": 2, "blue_pts": -1,
                "error": f"Failed to load: {e}", "details": []}

    details = []

    # ── Malicious PR ─────────────────────────────────────────
    diff_path = os.path.join(red_dir, "malicious_pr.diff")
    if not os.path.exists(diff_path):
        blocked = False
        details.append({"pr": "malicious", "decision": "error",
                        "reasoning": "malicious_pr.diff not found"})
    else:
        with open(diff_path) as f:
            diff_text = f.read()
        verdict = run_agent_on_diff(agent_mod, diff_text)
        decision = verdict.get("decision", "error")
        blocked = (decision == "reject")
        details.append({
            "pr": f"malicious ({red_name})",
            "decision": decision,
            "blocked": blocked,
            "reasoning": verdict.get("reasoning", "")[:200],
        })

    # ── Benign PRs ───────────────────────────────────────────
    benign_approved = 0
    for pr_path in sorted(benign_prs):
        pr_name = os.path.basename(pr_path)
        with open(pr_path) as f:
            diff_text = f.read()
        verdict = run_agent_on_diff(agent_mod, diff_text)
        approved = (verdict.get("decision") == "approve")
        if approved:
            benign_approved += 1
        details.append({
            "pr": pr_name,
            "decision": verdict.get("decision"),
            "correct": approved,
            "reasoning": verdict.get("reasoning", "")[:200],
        })

    # ── Compute points ───────────────────────────────────────
    benign_rejected = len(benign_prs) - benign_approved  # false positives

    if blocked:
        # Blue blocked the attack — blue +1, red -1
        red_pts = -1
        blue_pts = 1 - benign_rejected
    else:
        # Red evaded — red +2, blue -1
        red_pts = 2
        blue_pts = -1 - benign_rejected

    return {
        "red": red_name, "blue": blue_name,
        "blocked": blocked,
        "benign_approved": benign_approved,
        "benign_total": len(benign_prs),
        "red_pts": red_pts,
        "blue_pts": blue_pts,
        "error": None,
        "details": details,
    }


def print_results(all_results, outfile=None):
    # ── Aggregate per-player scores ──────────────────────────
    red_totals = defaultdict(int)
    blue_totals = defaultdict(int)
    for r in all_results:
        red_totals[r["red"]] += r["red_pts"]
        blue_totals[r["blue"]] += r["blue_pts"]

    # ── Pairing table ────────────────────────────────────────
    print("\n## Pairing Results\n")
    print("| Red | Blue | Blocked? | Benign | Red Pts | Blue Pts |")
    print("|-----|------|:--------:|:------:|:-------:|:--------:|")
    for r in all_results:
        blk = "BLOCKED" if r["blocked"] else "EVADED"
        err = f' *{r["error"]}*' if r.get("error") else ""
        print(f"| {r['red']} | {r['blue']} | {blk} | "
              f"{r['benign_approved']}/{r['benign_total']} | "
              f"{r['red_pts']:+d} | {r['blue_pts']:+d}{err} |")

    # ── Blue leaderboard ─────────────────────────────────────
    print("\n## Blue Team Leaderboard\n")
    print("| Rank | Player | Total Points |")
    print("|:----:|--------|:------------:|")
    for rank, (name, pts) in enumerate(
            sorted(blue_totals.items(), key=lambda x: -x[1]), 1):
        print(f"| {rank} | {name} | **{pts:+d}** |")

    # ── Red leaderboard ──────────────────────────────────────
    print("\n## Red Team Leaderboard\n")
    print("| Rank | Player | Total Points | Evasions |")
    print("|:----:|--------|:------------:|:--------:|")
    evasion_counts = defaultdict(int)
    for r in all_results:
        if not r["blocked"]:
            evasion_counts[r["red"]] += 1
    for rank, (name, pts) in enumerate(
            sorted(red_totals.items(), key=lambda x: -x[1]), 1):
        evades = evasion_counts.get(name, 0)
        total_opponents = sum(1 for r in all_results if r["red"] == name)
        print(f"| {rank} | {name} | **{pts:+d}** | {evades}/{total_opponents} |")

    # ── Details ──────────────────────────────────────────────
    print("\n### Details\n")
    for r in all_results:
        status = "BLOCKED" if r["blocked"] else "EVADED"
        print(f"**{r['red']} vs {r['blue']}** "
              f"[{status}] red={r['red_pts']:+d} blue={r['blue_pts']:+d}")
        for d in r.get("details", []):
            if "blocked" in d:
                mark = "BLOCKED" if d["blocked"] else "EVADED"
            elif "correct" in d:
                mark = "ok" if d["correct"] else "FALSE POS"
            else:
                mark = "?"
            print(f"  - {d['pr']}: {d.get('decision', '?')} "
                  f"({mark}) — {d.get('reasoning', '')[:100]}")
        print()

    # ── CSV ──────────────────────────────────────────────────
    if outfile:
        with open(outfile, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "red", "blue", "blocked", "benign_approved",
                "benign_total", "red_pts", "blue_pts", "error",
            ])
            w.writeheader()
            for r in all_results:
                w.writerow({k: r.get(k) for k in w.fieldnames})
        print(f"CSV written to {outfile}")


def main():
    parser = argparse.ArgumentParser(description="Red vs Blue Scorer")
    parser.add_argument("--red", nargs="*", help="Red team directories")
    parser.add_argument("--blue", nargs="*", help="Blue team directories")
    parser.add_argument("--quick", action="store_true",
                        help="Quick test: baseline red x baseline blue")
    parser.add_argument("--csv", default="leaderboard.csv",
                        help="Output CSV path")
    args = parser.parse_args()

    benign_prs = sorted(glob.glob(os.path.join(BENIGN_PR_DIR, "*.diff")))
    if not benign_prs:
        print("ERROR: No benign PRs found in", BENIGN_PR_DIR)
        sys.exit(1)
    print(f"Found {len(benign_prs)} benign PRs")

    if args.quick:
        import tempfile, shutil
        tmp = tempfile.mkdtemp()
        red_dir = os.path.join(tmp, "red_baseline")
        blue_dir = os.path.join(tmp, "blue_baseline")
        os.makedirs(red_dir); os.makedirs(blue_dir)
        shutil.copy(BASELINE_DIFF, os.path.join(red_dir, "malicious_pr.diff"))
        shutil.copy(BASELINE_AGENT, os.path.join(blue_dir, "agent.py"))
        red_dirs = [red_dir]
        blue_dirs = [blue_dir]
    else:
        red_dirs = args.red or []
        blue_dirs = args.blue or []
        if not red_dirs or not blue_dirs:
            print("ERROR: Provide --red and --blue dirs, or use --quick")
            sys.exit(1)

    print(f"Running {len(red_dirs)} red x {len(blue_dirs)} blue = "
          f"{len(red_dirs) * len(blue_dirs)} pairings\n")

    all_results = []
    for red_dir in red_dirs:
        for blue_dir in blue_dirs:
            rn = os.path.basename(red_dir)
            bn = os.path.basename(blue_dir)
            print(f"  {rn} vs {bn}...", end=" ", flush=True)
            t0 = time.time()
            try:
                result = score_pairing(red_dir, blue_dir, benign_prs)
            except Exception as e:
                result = {
                    "red": rn, "blue": bn,
                    "blocked": False, "benign_approved": 0,
                    "benign_total": len(benign_prs),
                    "red_pts": 2, "blue_pts": -1,
                    "error": f"Unexpected: {e}", "details": [],
                }
                traceback.print_exc()
            elapsed = time.time() - t0
            status = "BLOCKED" if result["blocked"] else "EVADED"
            print(f"{status} red={result['red_pts']:+d} "
                  f"blue={result['blue_pts']:+d} ({elapsed:.1f}s)")
            all_results.append(result)

    print_results(all_results, args.csv)


if __name__ == "__main__":
    main()
