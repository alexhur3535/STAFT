"""L2 (semantic tagging) baseline: M1 / M2 / compression per trace.

Usage:
    # IPI (default, backwards-compatible)
    python -m forensic.pipeline.run_l2_baseline

    # Misuse / misbehavior (non-IPI)
    python -m forensic.pipeline.run_l2_baseline \\
        --result_dir results/osharm_misuse_L0 \\
        --output results/l2_baseline_misuse.json \\
        --l2_traces results/l2_traces_misuse.jsonl \\
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

from forensic.abstraction import L1PII, L2Semantic
from forensic.metrics import PrivacyLeakageMeter
from forensic.trace_loader import load_all_traces


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
        default=REPO_ROOT / "results" / "l2_baseline_report.json",
        help="Output JSON path (default: results/l2_baseline_report.json)",
    )
    parser.add_argument(
        "--l2_traces",
        type=Path,
        default=REPO_ROOT / "results" / "l2_traces.jsonl",
        help="Output JSONL path for serialized L2 traces (default: results/l2_traces.jsonl)",
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

    l2 = L2Semantic()
    l1_for_scope = L1PII()
    meter = PrivacyLeakageMeter(entities=l1_for_scope.entities)
    print(f"M1 scope: {l1_for_scope.entities}\n")

    rows: list[dict] = []
    serialized_l2: list[dict] = []
    t0 = time.time()
    for i, raw in enumerate(traces, 1):
        elapsed = time.time() - t0
        if i % 2 == 0 or i == 1:
            tag = f"{raw.gt.category}/{raw.gt.vector or raw.gt.incident_type}"
            print(f"  [{i}/{len(traces)}] elapsed={elapsed:.0f}s | {tag} "
                  f"(steps={len(raw.steps)})", flush=True)
        try:
            abstracted = l2.apply(raw)
        except Exception as e:
            print(f"  [{i}] L2 EXCEPTION: {e!r}")
            continue
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
            "n_steps": len(raw.steps),
            "pii_recall": leak.pii_recall,
            "bleu2": leak.bleu2,
            "n_pii_in_raw": leak.n_pii_in_raw,
            "n_pii_intersect": leak.n_pii_intersect,
            "n_tokens_raw": leak.n_tokens_raw,
            "n_tokens_abstracted": leak.n_tokens_abstracted,
        })
        serialized_l2.append({
            "trace_id": raw.trace_id,
            "gt": {
                "incident_type": raw.gt.incident_type,
                "category": raw.gt.category, "vector": raw.gt.vector,
                "goal": raw.gt.goal, "base_task_id": raw.gt.base_task_id,
            },
            "instruction": raw.instruction,
            "steps_l2": [
                {
                    "obs_summary": s.a11y_tree,
                    "reasoning_tag": s.response,
                    "actions": s.actions,
                }
                for s in abstracted.steps
            ],
        })

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s. L2 op stats: {l2.stats}\n")

    by_bucket: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        key = r["vector"] if r["vector"] else r["category"]
        by_bucket[key].append(r)

    def med(xs: list[float]) -> float:
        return statistics.median(xs) if xs else 0.0

    def mean(xs: list[float]) -> float:
        return statistics.mean(xs) if xs else 0.0

    print("=" * 90)
    print(f"PER-{bucket_label.upper()} AGGREGATE (L0 -> L2)")
    print("=" * 90)
    print(f"{bucket_label:<28}{'n':>4}{'M1 mean':>10}{'M1 med':>9}"
          f"{'M2 mean':>10}{'M2 med':>9}{'tok_raw':>10}{'tok_abs':>10}")
    for v in sorted(by_bucket):
        items = by_bucket[v]
        m1s = [r["pii_recall"] for r in items]
        m2s = [r["bleu2"] for r in items]
        tr = [r["n_tokens_raw"] for r in items]
        ta = [r["n_tokens_abstracted"] for r in items]
        print(f"  {v:<26}{len(items):>4}"
              f"{mean(m1s):>10.3f}{med(m1s):>9.3f}"
              f"{mean(m2s):>10.3f}{med(m2s):>9.3f}"
              f"{mean(tr):>10.0f}{mean(ta):>10.0f}")
    all_m1 = [r["pii_recall"] for r in rows]
    all_m2 = [r["bleu2"] for r in rows]
    all_tr = [r["n_tokens_raw"] for r in rows]
    all_ta = [r["n_tokens_abstracted"] for r in rows]
    print("-" * 90)
    print(f"  {'OVERALL':<26}{len(rows):>4}"
          f"{mean(all_m1):>10.3f}{med(all_m1):>9.3f}"
          f"{mean(all_m2):>10.3f}{med(all_m2):>9.3f}"
          f"{mean(all_tr):>10.0f}{mean(all_ta):>10.0f}")
    if all_tr and all_ta:
        compression = 1 - (mean(all_ta) / mean(all_tr))
        print(f"\n  Mean token compression: {100*compression:.1f}% "
              f"(L2 keeps ~{mean(all_ta)/mean(all_tr)*100:.1f}% of raw tokens)")
    print()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        json.dump({"rows": rows, "l2_stats": l2.stats}, f, indent=2)
    print(f"Wrote report -> {args.output}")
    args.l2_traces.parent.mkdir(parents=True, exist_ok=True)
    with args.l2_traces.open("w") as f:
        for entry in serialized_l2:
            f.write(json.dumps(entry) + "\n")
    print(f"Wrote L2 traces -> {args.l2_traces}")


if __name__ == "__main__":
    main()
