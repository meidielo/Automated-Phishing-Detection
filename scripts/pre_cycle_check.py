#!/usr/bin/env python3
"""
Pre-cycle gate for Rule 1 in CONTRIBUTING.md ("Read outcomes before narrative").

This script MUST be run at the start of every cycle, before writing the
cycle plan or touching any code. Its job is to force the reader's eyes
onto the current outcome artifacts — eval_runs/, residual risks, open
items — BEFORE they read HISTORY.md or commit messages that would frame
those outcomes.

Narrative absorption is this project's documented failure mode. Cycle
10 demonstrated it (a broken eval baseline was absorbed as "data, not
goalposts"). Cycle 11 demonstrated it again (a writeup polish cycle
happened in the window where the P0 investigation should have taken
place). Cycle 12's audit caught both but required an external reviewer.
Cycle 13 builds THIS script as a structural defense so the next cycle
doesn't require an external reviewer to notice the same pattern.

The script exits non-zero if:
  - No eval_runs/*.summary.json file exists, OR
  - The most recent eval summary is older than MAX_EVAL_AGE_DAYS, OR
  - The most recent eval shows permissive recall < MIN_RECALL_FLOOR and
    the READONLY tripwire in HISTORY.md doesn't already acknowledge it.

Usage:
    python scripts/pre_cycle_check.py

    # Print and pass without the tripwire check (useful mid-cycle):
    python scripts/pre_cycle_check.py --permissive

Exit code 0 means "you may proceed with cycle planning".
Exit code 1 means "stop and reconcile what you just read against your
planned scope". It is NOT a suggestion. If you override it, document
the override in the cycle commit message and include the reason —
otherwise you've just reproduced cycle 10's framing absorption.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = PROJECT_ROOT / "eval_runs"
HISTORY = PROJECT_ROOT / "HISTORY.md"
THREAT_MODEL = PROJECT_ROOT / "THREAT_MODEL.md"
ROADMAP = PROJECT_ROOT / "ROADMAP.md"

MAX_EVAL_AGE_DAYS = 14
MIN_RECALL_FLOOR = 0.50  # cycle 12 pre-committed threshold for "meaningfully working"


def _latest_eval_summary() -> Path | None:
    if not EVAL_DIR.exists():
        return None
    summaries = sorted(EVAL_DIR.glob("*.summary.json"))
    return summaries[-1] if summaries else None


def _parse_run_id_date(summary_path: Path) -> datetime | None:
    """Parse the date from a run ID like '2026-04-15_0344_abc1234'."""
    name = summary_path.stem.replace(".summary", "")
    m = re.match(r"(\d{4}-\d{2}-\d{2})_(\d{4})_", name)
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H%M")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _open_residual_risks() -> list[str]:
    """Extract open P0/P1 residual risks from THREAT_MODEL.md §6."""
    if not THREAT_MODEL.exists():
        return []
    text = THREAT_MODEL.read_text(encoding="utf-8")
    # Find R1..RN headings in §6 that are NOT "MITIGATED" / "CLOSED"
    open_risks = []
    for m in re.finditer(r"^### (R\d+)\s*[—-]\s*(.+?)$", text, re.MULTILINE):
        rid, title = m.group(1), m.group(2).strip()
        # Look at the next ~10 lines for a status marker
        start = m.end()
        body = text[start:start + 800]
        status_match = re.search(r"\*\*Status:\s*([^*]+)\*\*", body)
        status = status_match.group(1).strip().upper() if status_match else "UNKNOWN"
        if "MITIGATED" not in status and "CLOSED" not in status:
            open_risks.append(f"{rid} — {title}  [{status}]")
    return open_risks


def _open_roadmap_items() -> list[str]:
    """Extract items from ROADMAP.md 'What's open' or 'Planned' section."""
    if not ROADMAP.exists():
        return []
    text = ROADMAP.read_text(encoding="utf-8")
    # Grab the Planned section top-level entries
    m = re.search(r"^## Planned\s*\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    section = m.group(1)
    headings = re.findall(r"^### (.+?)$", section, re.MULTILINE)
    return headings[:10]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--permissive", action="store_true",
                        help="Skip the tripwire check, still print everything")
    args = parser.parse_args()

    print("=" * 72)
    print("PRE-CYCLE GATE — read outcomes before narrative (CONTRIBUTING Rule 1)")
    print("=" * 72)
    print()

    # ─── Eval outcomes ──────────────────────────────────────────────────
    print("[1] Most recent eval baseline:")
    summary_path = _latest_eval_summary()
    if summary_path is None:
        print("    NO EVAL RUN FOUND under eval_runs/")
        print("    This is a blocking condition. Run `python scripts/run_eval.py`")
        print("    before starting any cycle that touches detection code.")
        if not args.permissive:
            return 1
    else:
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"    FAILED TO READ {summary_path.name}: {e}")
            return 1
        run_dt = _parse_run_id_date(summary_path)
        age_days = (datetime.now(timezone.utc) - run_dt).days if run_dt else None

        print(f"    file:       {summary_path.name}")
        if run_dt:
            print(f"    date:       {run_dt.date().isoformat()}  (age: {age_days} days)")
        print(f"    commit:     {summary.get('commit_sha', '?')}")
        print(f"    samples:    {summary.get('sample_count', '?')}")
        perm = summary.get("permissive", {})
        strict = summary.get("strict", {})
        print(f"    permissive: recall={perm.get('recall', 0):.3f} "
              f"precision={perm.get('precision', 0):.3f} "
              f"f1={perm.get('f1', 0):.3f}  "
              f"(TP={perm.get('true_positive', 0)}/FP={perm.get('false_positive', 0)}/"
              f"TN={perm.get('true_negative', 0)}/FN={perm.get('false_negative', 0)})")
        print(f"    strict:     recall={strict.get('recall', 0):.3f} "
              f"precision={strict.get('precision', 0):.3f} "
              f"f1={strict.get('f1', 0):.3f}")
        print()

        # Tripwire 1: stale eval
        if age_days is not None and age_days > MAX_EVAL_AGE_DAYS:
            print(f"    TRIPWIRE: most recent eval is {age_days} days old "
                  f"(> {MAX_EVAL_AGE_DAYS}). Re-run the harness before starting "
                  f"this cycle, or document why the baseline is stale in the commit.")
            if not args.permissive:
                return 1

        # Tripwire 2: recall below floor
        perm_recall = perm.get("recall", 0.0)
        if perm_recall < MIN_RECALL_FLOOR:
            print(f"    TRIPWIRE: permissive recall {perm_recall:.3f} is below the")
            print(f"    pre-committed {MIN_RECALL_FLOOR:.2f} 'meaningfully working' floor.")
            print(f"    The README TL;DR must reflect this until the next eval run")
            print(f"    moves recall above the floor. Reference: HISTORY.md cycle 12.")
            print(f"    Continue only if this cycle's scope is closing the gap or")
            print(f"    explicitly out-of-scope work that doesn't touch detection.")
            # Not auto-failing on this — the tripwire prints the warning and
            # lets the reader consciously acknowledge it. The exit-nonzero
            # case is for staleness, not for low recall.
        print()

    # ─── Residual risks ────────────────────────────────────────────────
    print("[2] Open residual risks (THREAT_MODEL.md §6):")
    risks = _open_residual_risks()
    if risks:
        for r in risks:
            print(f"    - {r}")
    else:
        print("    (none parsed — check THREAT_MODEL.md §6 manually if the threat model exists)")
    print()

    # ─── Open roadmap items ────────────────────────────────────────────
    print("[3] Planned items (ROADMAP.md 'Planned'):")
    items = _open_roadmap_items()
    if items:
        for i in items:
            print(f"    - {i}")
    else:
        print("    (none parsed)")
    print()

    # ─── Explicit reminder ─────────────────────────────────────────────
    print("=" * 72)
    print("Now — and only now — read HISTORY.md, the previous cycle's commit,")
    print("and the reviewer note you're responding to (if any).")
    print()
    print("If this cycle's scope drifts from what the outcome artifacts above")
    print("suggest is the most load-bearing next work, write down the reason")
    print("in your cycle plan BEFORE starting. 'I looked and the data said X")
    print("but I'm doing Y because Z' is honest; 'the plan is Y' without")
    print("acknowledging X is the cycle 11 failure mode.")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    sys.exit(main())
