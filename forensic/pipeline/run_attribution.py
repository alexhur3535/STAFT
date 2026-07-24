"""Attribution accuracy across L0/L1/L2 × B1, B2, LOO-LLM.

Reports, per (method × level), top-1 / top-3 / MRR on the behavioral set
(n=50) and the strict subset (n=10, traces with a judge-set violation_step).
Writes a JSON report and a console table.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.abstraction import L0Identity, L1PII
from forensic.attribution import (
    AttributionAlgorithm,
    AttributionResult,
    B1Random,
    B2Keyword,
    LOOLLMCounterfactual,
)
from forensic.trace_loader import GroundTruth, Trace, TraceStep, load_all_traces

L0_RESULTS = REPO_ROOT / "results" / "osharm_ipi_L0"
L2_TRACES_PATH = REPO_ROOT / "results" / "l2_traces.jsonl"
OUT_PATH = REPO_ROOT / "results" / "attribution_report.json"


def load_l2_traces_from_jsonl(path: Path, l0_traces: list[Trace]) -> list[Trace]:
    """Reconstruct Trace objects from the L2 JSONL written by run_l2_baseline."""
    l0_by_id = {t.trace_id: t for t in l0_traces}
    out: list[Trace] = []
    with path.open() as f:
        for line in f:
            d = json.loads(line)
            tid = d["trace_id"]
            base = l0_by_id.get(tid)
            if base is None:
                continue
            new_steps = [
                TraceStep(
                    a11y_tree=s.get("obs_summary", ""),
                    screenshot_file="",
                    response=s.get("reasoning_tag", ""),
                    actions=list(s.get("actions", [])),
                )
                for s in d.get("steps_l2", [])
            ]
            out.append(
                replace(
                    base,
                    steps=new_steps,
                    final_caption=None,
                    gt=deepcopy(base.gt),
                )
            )
    return out


def has_violation(trace: Trace) -> bool:
    if not trace.judge_verdict:
        return False
    j = trace.judge_verdict.get("judgment", {})
    if not isinstance(j, dict):
        return False
    return j.get("violation_step") not in (None, "null", "None")


def evaluate(results: list[AttributionResult], n: int | None = None) -> dict:
    if not results:
        return {"n": 0, "top1": 0.0, "top3": 0.0, "mrr": 0.0}
    if n is None:
        n = len(results)
    top1 = sum(1 for r in results if r.top1_correct) / n
    top3 = sum(1 for r in results if r.topk_correct(3)) / n
    mrr = sum(r.reciprocal_rank for r in results) / n
    return {"n": n, "top1": top1, "top3": top3, "mrr": mrr}


def main() -> None:
    print(f"Loading L0 traces from {L0_RESULTS} ...")
    l0 = load_all_traces(L0_RESULTS)
    print(f"  Loaded {len(l0)} L0 traces.")

    print("Applying L1 (Presidio PII masking) in-memory ...")
    t0 = time.time()
    l1_op = L1PII()
    l1 = [l1_op.apply(t) for t in l0]
    print(f"  L1 applied in {time.time()-t0:.0f}s.")

    print(f"Loading L2 traces from {L2_TRACES_PATH} ...")
    l2 = load_l2_traces_from_jsonl(L2_TRACES_PATH, l0)
    print(f"  Loaded {len(l2)} L2 traces.")

    levels: dict[str, list[Trace]] = {"L0": l0, "L1": l1, "L2": l2}

    # Set of trace_ids with violation (strict subset)
    strict_ids = {t.trace_id for t in l0 if has_violation(t)}
    print(f"\nStrict subset (violation_step set): {len(strict_ids)} / {len(l0)} traces.\n")

    methods: list[AttributionAlgorithm] = [
        B1Random(),
        B2Keyword(),
        LOOLLMCounterfactual(),
    ]

    table_rows: list[dict] = []
    raw_per_method_level: dict[str, dict[str, list[dict]]] = defaultdict(dict)

    for method in methods:
        for level_name, traces in levels.items():
            t0 = time.time()
            print(f"== {method.name} on {level_name} ({len(traces)} traces) ...")
            results = method.attribute_many(traces)
            elapsed = time.time() - t0
            behavioral = evaluate(results)
            strict_results = [r for r in results if r.trace_id in strict_ids]
            strict = evaluate(strict_results, n=len(strict_results) or 1)
            row = {
                "method": method.name,
                "level": level_name,
                "elapsed_s": round(elapsed, 1),
                "behavioral_n": behavioral["n"],
                "behavioral_top1": round(behavioral["top1"], 3),
                "behavioral_top3": round(behavioral["top3"], 3),
                "behavioral_mrr": round(behavioral["mrr"], 3),
                "strict_n": strict["n"],
                "strict_top1": round(strict["top1"], 3),
                "strict_top3": round(strict["top3"], 3),
                "strict_mrr": round(strict["mrr"], 3),
            }
            table_rows.append(row)
            raw_per_method_level[method.name][level_name] = [
                {
                    "trace_id": r.trace_id,
                    "gt_vector": r.gt_vector,
                    "top1": r.top1,
                    "rank_of_gt": r.rank_of_gt,
                    "scores": r.scores,
                }
                for r in results
            ]
            stats = getattr(method, "stats", None)
            print(f"   behavioral: top1={behavioral['top1']:.3f} top3={behavioral['top3']:.3f} mrr={behavioral['mrr']:.3f}")
            print(f"   strict    : top1={strict['top1']:.3f} top3={strict['top3']:.3f} mrr={strict['mrr']:.3f}")
            print(f"   elapsed   : {elapsed:.1f}s   stats={stats}")
            print()

    # Pretty table
    print("=" * 96)
    print("ATTRIBUTION ACCURACY TABLE")
    print("=" * 96)
    print(
        f"{'method':<14}{'level':<6}"
        f"{'beh_top1':>10}{'beh_top3':>10}{'beh_mrr':>10}"
        f"   |"
        f"{'str_top1':>10}{'str_top3':>10}{'str_mrr':>10}"
    )
    for row in table_rows:
        print(
            f"  {row['method']:<12}{row['level']:<6}"
            f"{row['behavioral_top1']:>10.3f}{row['behavioral_top3']:>10.3f}{row['behavioral_mrr']:>10.3f}"
            f"   |"
            f"{row['strict_top1']:>10.3f}{row['strict_top3']:>10.3f}{row['strict_mrr']:>10.3f}"
        )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w") as f:
        json.dump(
            {"summary": table_rows, "per_trace": raw_per_method_level, "strict_ids": sorted(strict_ids)},
            f,
            indent=2,
        )
    print(f"\nWrote attribution report -> {OUT_PATH}")


if __name__ == "__main__":
    main()
