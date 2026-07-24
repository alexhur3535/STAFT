"""L1 (Presidio PII masking) baseline: M1 (PII recall) and M2 (BLEU-2) per trace.

Usage:
    # IPI (default, backwards-compatible)
    python -m forensic.pipeline.run_l1_baseline

    # Misuse / misbehavior (non-IPI)
    python -m forensic.pipeline.run_l1_baseline \\
        --result_dir results/osharm_misuse_L0 \\
        --output results/l1_baseline_misuse.json \\
        --non-ipi
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.abstraction import L1PII
from forensic.metrics import PrivacyLeakageMeter
from forensic.trace_loader import load_all_traces


def _bucket_key(raw) -> str:
    """Aggregation bucket: IPI groups by injection vector; non-IPI by category."""
    return raw.gt.vector if raw.gt.vector else raw.gt.category


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--result_dir",
        type=Path,
        default=REPO_ROOT / "results" / "osharm_ipi_L0",
        help="Trace root directory (default: results/osharm_ipi_L0)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "results" / "l1_baseline_report.json",
        help="Output JSON path (default: results/l1_baseline_report.json)",
    )
    parser.add_argument(
        "--non-ipi",
        action="store_true",
        help="Load misuse / misbehavior traces (no __inject__ filter, no cross-check)",
    )
    args = parser.parse_args()

    require_inject = not args.non_ipi
    strict_cross_check = not args.non_ipi
    bucket_label = "vector" if require_inject else "category"

    print(f"Loading L0 traces from {args.result_dir} (non_ipi={args.non_ipi}) ...")
    traces = load_all_traces(
        args.result_dir,
        require_inject_suffix=require_inject,
        strict_cross_check=strict_cross_check,
    )
    print(f"  Loaded {len(traces)} traces.\n")

    l1 = L1PII()
    meter = PrivacyLeakageMeter(entities=l1.entities)
    print(f"M1 measurement scope: {l1.entities}\n")

    rows: list[dict] = []
    samples_for_print: dict[str, dict] = {}
    t0 = time.time()
    for i, raw in enumerate(traces, 1):
        elapsed = time.time() - t0
        if i % 5 == 0 or i == 1:
            tag = f"{raw.gt.category}/{raw.gt.vector or raw.gt.incident_type}"
            print(f"  [{i}/{len(traces)}] elapsed={elapsed:.0f}s | {tag}")
        abstracted = l1.apply(raw)
        leak = meter.measure_trace(raw, abstracted)
        rows.append({
            "trace_id": raw.trace_id,
            "incident_type": raw.gt.incident_type,
            "category": raw.gt.category,
            "vector": raw.gt.vector,
            "goal": raw.gt.goal,
            "violation_step":
                raw.judge_verdict.get("judgment", {}).get("violation_step")
                if raw.judge_verdict else None,
            "pii_recall": leak.pii_recall,
            "bleu2": leak.bleu2,
            "n_pii_in_raw": leak.n_pii_in_raw,
            "n_pii_intersect": leak.n_pii_intersect,
            "n_tokens_raw": leak.n_tokens_raw,
            "n_tokens_abstracted": leak.n_tokens_abstracted,
        })
        bucket = _bucket_key(raw)
        if bucket not in samples_for_print:
            samples_for_print[bucket] = {
                "trace_id": raw.trace_id,
                "raw_instruction": raw.instruction,
                "abs_instruction": abstracted.instruction,
                "raw_step0_a11y_excerpt":
                    (raw.steps[0].a11y_tree if raw.steps else "")[:400],
                "abs_step0_a11y_excerpt":
                    (abstracted.steps[0].a11y_tree if abstracted.steps else "")[:400],
                "raw_step0_response": (raw.steps[0].response if raw.steps else "")[:300],
                "abs_step0_response":
                    (abstracted.steps[0].response if abstracted.steps else "")[:300],
            }

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s. Aggregating...\n")

    by_bucket: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        key = r["vector"] if r["vector"] else r["category"]
        by_bucket[key].append(r)

    def med(xs: list[float]) -> float:
        return statistics.median(xs) if xs else 0.0

    def mean(xs: list[float]) -> float:
        return statistics.mean(xs) if xs else 0.0

    print("=" * 84)
    print(f"PER-{bucket_label.upper()} AGGREGATE (L0 -> L1)")
    print("=" * 84)
    print(f"{bucket_label:<28}{'n':>4}{'M1 mean':>10}{'M1 med':>9}"
          f"{'M2 mean':>10}{'M2 med':>9}{'tok_lost':>11}")
    for v in sorted(by_bucket):
        items = by_bucket[v]
        m1s = [r["pii_recall"] for r in items]
        m2s = [r["bleu2"] for r in items]
        tok_delta = [r["n_tokens_raw"] - r["n_tokens_abstracted"] for r in items]
        print(f"  {v:<26}{len(items):>4}"
              f"{mean(m1s):>10.3f}{med(m1s):>9.3f}"
              f"{mean(m2s):>10.3f}{med(m2s):>9.3f}"
              f"{mean(tok_delta):>11.1f}")
    all_m1 = [r["pii_recall"] for r in rows]
    all_m2 = [r["bleu2"] for r in rows]
    print("-" * 84)
    print(f"  {'OVERALL':<26}{len(rows):>4}"
          f"{mean(all_m1):>10.3f}{med(all_m1):>9.3f}"
          f"{mean(all_m2):>10.3f}{med(all_m2):>9.3f}")
    print()

    n_with_pii = sum(1 for r in rows if r["n_pii_in_raw"] > 0)
    n_zero_pii = len(rows) - n_with_pii
    print(f"Traces with detected PII in raw L0: {n_with_pii} / {len(rows)}")
    print(f"Traces with no detected PII (M1 = 0 trivially): {n_zero_pii}")
    if n_with_pii:
        pii_counts = sorted([r["n_pii_in_raw"] for r in rows if r["n_pii_in_raw"]])
        print(f"  |P0| distribution: min={min(pii_counts)}, "
              f"median={statistics.median(pii_counts):.1f}, max={max(pii_counts)}, "
              f"total={sum(pii_counts)}")
    print()

    print("=" * 84)
    print(f"SAMPLE DIFFS (one trace per {bucket_label})")
    print("=" * 84)
    for v in sorted(samples_for_print):
        s = samples_for_print[v]
        print(f"\n-- {bucket_label}: {v} (trace={s['trace_id'][:70]}...) --")
        if s["raw_instruction"] != s["abs_instruction"]:
            print(f"  [instruction CHANGED]")
            print(f"    raw : {s['raw_instruction']}")
            print(f"    abs : {s['abs_instruction']}")
        else:
            print(f"  [instruction unchanged]")
        if s["raw_step0_a11y_excerpt"] != s["abs_step0_a11y_excerpt"]:
            print(f"  [step0 a11y_tree (first 400ch) CHANGED]")
            print(f"    raw : {s['raw_step0_a11y_excerpt']!r}")
            print(f"    abs : {s['abs_step0_a11y_excerpt']!r}")
        else:
            print(f"  [step0 a11y_tree unchanged in first 400ch]")
        if s["raw_step0_response"] != s["abs_step0_response"]:
            print(f"  [step0 response (first 300ch) CHANGED]")
            print(f"    raw : {s['raw_step0_response']!r}")
            print(f"    abs : {s['abs_step0_response']!r}")
        else:
            print(f"  [step0 response unchanged in first 300ch]")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        json.dump({"rows": rows}, f, indent=2)
    print(f"\nWrote report -> {args.output}")


if __name__ == "__main__":
    main()
