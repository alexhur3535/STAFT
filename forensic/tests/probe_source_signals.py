"""One-shot diagnostic: probe whether attribution signals are extractable from
each trace, across all 50 IPI traces. Outputs:

  (1) Vector × injection-content-presence matrix
      → Can we locate the injection content in a11y_tree text?
  (2) Per-vector a11y_tree size + cue keyword presence
      → What patterns distinguish each vector's source region?
  (3) Judge verdict schema (violation_step, etc.) — informs cross-validation
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.trace_loader import load_all_traces

RESULTS = REPO_ROOT / "results" / "osharm_ipi_L0"


def first_step_containing(text: str, traces_steps) -> int | None:
    for i, s in enumerate(traces_steps):
        if text and text[:40] in s.a11y_tree:
            return i
    return None


def main() -> None:
    traces = load_all_traces(RESULTS)
    print(f"Loaded {len(traces)} traces from {RESULTS}\n")

    # ---- (1) injection content presence in a11y_tree ----
    print("=" * 70)
    print("CHECK 1: injection content presence in a11y_tree (by vector)")
    print("=" * 70)
    by_vec_total: Counter = Counter()
    by_vec_present: Counter = Counter()
    by_vec_first_step: dict = defaultdict(list)
    for t in traces:
        v = t.gt.vector
        by_vec_total[v] += 1
        step = first_step_containing(t.gt.injection_content, t.steps)
        if step is not None:
            by_vec_present[v] += 1
            by_vec_first_step[v].append(step)

    print(f"{'vector':<26}{'present/total':>15}{'first_step (median)':>22}")
    for v in sorted(by_vec_total):
        present = by_vec_present.get(v, 0)
        total = by_vec_total[v]
        steps = sorted(by_vec_first_step.get(v, []))
        median = steps[len(steps) // 2] if steps else "—"
        print(f"  {v:<24}{present:>4}/{total:<10}{str(median):>22}")
    print()

    # ---- (2) per-vector a11y_tree cue keywords ----
    print("=" * 70)
    print("CHECK 2: a11y_tree size + UI cue keywords by vector")
    print("=" * 70)
    cues = {
        "website": ("Chrome", "Address bar", "url", "http"),
        "libreoffice_writer": ("LibreOffice", "Writer", ".odt", ".docx"),
        "thunderbird_mail_received": ("Inbox", "Thunderbird", "From:"),
        "thunderbird_mail_draft": ("Compose", "Subject:", "To:"),
        "desktop_notification": ("notification", "popup", "IMPORTANT"),
        "vs_code": ("Visual Studio Code", "Explorer", ".py", "Editor"),
    }
    by_vec_a11y_avg: dict = defaultdict(list)
    by_vec_cue_hits: dict = defaultdict(lambda: defaultdict(int))
    for t in traces:
        v = t.gt.vector
        for s in t.steps:
            by_vec_a11y_avg[v].append(len(s.a11y_tree))
            for cue in cues.get(v, ()):
                if cue.lower() in s.a11y_tree.lower():
                    by_vec_cue_hits[v][cue] += 1
    for v in sorted(by_vec_a11y_avg):
        sizes = by_vec_a11y_avg[v]
        avg = sum(sizes) / len(sizes) if sizes else 0
        cue_summary = ", ".join(
            f"{c}={by_vec_cue_hits[v][c]}" for c in cues.get(v, ())
        ) or "(no cues defined)"
        print(f"  {v:<28} avg_a11y_chars={avg:7.0f}  cues: {cue_summary}")
    print()

    # ---- (3) judge verdict schema ----
    print("=" * 70)
    print("CHECK 3: judge_verdict schema sampling")
    print("=" * 70)
    keys_seen: Counter = Counter()
    sample_verdicts = []
    for t in traces:
        if t.judge_verdict:
            for jname, payload in t.judge_verdict.items():
                if isinstance(payload, dict):
                    for k in payload:
                        keys_seen[f"{jname}.{k}"] += 1
                    if len(sample_verdicts) < 3:
                        sample_verdicts.append((t.trace_id, jname, payload))
    print("Verdict keys (count across traces):")
    for k, c in keys_seen.most_common():
        print(f"  {k:<40} {c}")
    print()
    print("Sample verdicts (up to 3):")
    for tid, jname, payload in sample_verdicts:
        print(f"  trace={tid[:60]}…  judge={jname}")
        print(f"    {json.dumps(payload, indent=2, default=str)[:600]}")
        print()

    # ---- (4) violation_step + ground-truth check ----
    print("=" * 70)
    print("CHECK 4: violation_step distribution + does a non-zero verdict match GT?")
    print("=" * 70)
    has_violation = 0
    no_violation = 0
    for t in traces:
        verdict_text = json.dumps(t.judge_verdict or {})
        if '"violation_step"' in verdict_text and '"violation_step": null' not in verdict_text:
            has_violation += 1
        else:
            no_violation += 1
    print(f"  traces with violation_step set : {has_violation}")
    print(f"  traces without violation       : {no_violation}")

    # ---- (5) print one full vector x goal sample of injection in a11y_tree ----
    print()
    print("=" * 70)
    print("CHECK 5: snippet of injection content inside a11y_tree (one trace)")
    print("=" * 70)
    sample = next(
        (t for t in traces if first_step_containing(t.gt.injection_content, t.steps) is not None),
        None,
    )
    if sample:
        i = first_step_containing(sample.gt.injection_content, sample.steps)
        a = sample.steps[i].a11y_tree
        idx = a.find(sample.gt.injection_content[:30])
        ctx_start = max(0, idx - 120)
        ctx_end = min(len(a), idx + len(sample.gt.injection_content) + 120)
        print(f"  trace = {sample.trace_id}")
        print(f"  vector = {sample.gt.vector}  goal = {sample.gt.goal}")
        print(f"  step  = {i}")
        print(f"  injection content (40ch): {sample.gt.injection_content[:80]!r}")
        print(f"  a11y_tree context [{ctx_start}:{ctx_end}]:")
        print("  " + "-" * 60)
        for line in a[ctx_start:ctx_end].splitlines():
            print(f"  | {line}")
        print("  " + "-" * 60)


if __name__ == "__main__":
    main()
