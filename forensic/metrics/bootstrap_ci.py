"""Bootstrap 95% CI on attribution accuracy from a run_attribution report.

Usage:
    python -m forensic.metrics.bootstrap_ci results/attribution_report.json

Per (method × level): behavioral and strict-subset top-1 mean with 95% CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

N_BOOTSTRAP = 10_000
SEED = 42
CONF = 0.95


def bootstrap_mean_ci(hits, n_boot=N_BOOTSTRAP, conf=CONF, seed=SEED):
    hits = np.asarray(hits, dtype=float)
    n = len(hits)
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_boot, n))
    boots = hits[idx].mean(axis=1)
    alpha = (1 - conf) / 2
    lo, hi = np.quantile(boots, [alpha, 1 - alpha])
    return float(hits.mean()), float(lo), float(hi)


def report_pair(method: str, level: str, traces: list[dict], strict_ids: set[str]) -> None:
    full = [int(t["top1"] == t["gt_vector"]) for t in traces]
    strict = [
        int(t["top1"] == t["gt_vector"])
        for t in traces
        if t["trace_id"] in strict_ids
    ]

    mu_f, lo_f, hi_f = bootstrap_mean_ci(full)
    print(
        f"{method:<10} {level:<3} behavioral n={len(full):>3}  "
        f"mean={mu_f:.3f}  CI=[{lo_f:.3f}, {hi_f:.3f}]"
    )

    if not strict:
        print(f"{method:<10} {level:<3} strict     n=  0  (no strict-subset traces)\n")
        return

    mu_s, lo_s, hi_s = bootstrap_mean_ci(strict)
    print(
        f"{method:<10} {level:<3} strict     n={len(strict):>3}  "
        f"mean={mu_s:.3f}  CI=[{lo_s:.3f}, {hi_s:.3f}]"
    )

    if hi_s < mu_f:
        verdict = "STRICT < BEHAVIORAL — strict-subset paradox supported"
    elif lo_s > mu_f:
        verdict = "STRICT > BEHAVIORAL — opposite of paradox"
    else:
        verdict = "OVERLAP — gap NOT significant at 95%"
    print(f"           -> {verdict}\n")


def main(path: str) -> None:
    data = json.loads(Path(path).read_text())
    strict_ids = set(data.get("strict_ids", []))
    per_trace = data["per_trace"]

    print(
        f"Bootstrap CI report (n_boot={N_BOOTSTRAP}, conf={CONF * 100:.0f}%, "
        f"strict subset n={len(strict_ids)})\n"
    )

    for method, levels in per_trace.items():
        for level, traces in levels.items():
            report_pair(method, level, traces, strict_ids)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m forensic.metrics.bootstrap_ci <attribution_report.json>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
