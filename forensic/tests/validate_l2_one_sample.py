"""L2 1-sample validation — 4 checks before scaling to 50 traces.

Picks one trace per vector (up to 6 traces) and runs L2 abstraction, then
verifies:

  V1. JSON schema integrity — every step produced a parseable {obs_summary,
      reasoning_tag, actions[*]} envelope. Reports parse-failure rate.

  V2. Schema-conformant tags — every action/target/intent tag is in the
      whitelisted enumeration (no LLM-invented tags).

  V3. Source-region signal preservation — for a trace whose ground-truth
      vector is desktop_notification, at least one step's actions list must
      include target POPUP_NOTIFICATION; similarly for other vectors.

  V4. BLEU-2 compression — abstracted-vs-raw BLEU-2 should be < 0.30 on the
      flattened text. Higher = L2 not compressing enough.
"""

from __future__ import annotations

import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.abstraction import L2Semantic
from forensic.metrics import PrivacyLeakageMeter
from forensic.trace_loader import load_all_traces

L0_RESULTS = REPO_ROOT / "results" / "osharm_ipi_L0"

ALLOWED_ACTIONS = {
    "CLICK", "TYPE", "DRAG", "RUN_CMD", "OPEN_APP", "NAVIGATE",
    "SEND_MAIL", "DOWNLOAD", "READ", "SCROLL", "REFUSE", "NO_OP",
    "UNKNOWN_ACTION",
}
ALLOWED_TARGETS = {
    "APP_CHROME", "APP_THUNDERBIRD", "APP_VS_CODE",
    "APP_LIBREOFFICE_WRITER", "APP_LIBREOFFICE_CALC", "APP_LIBREOFFICE_IMPRESS",
    "APP_GIMP", "APP_TERMINAL", "APP_FILE_MANAGER", "APP_OS_DESKTOP",
    "FILE_TEXT", "FILE_CODE", "FILE_DOC", "FILE_IMAGE", "FILE_ARCHIVE",
    "URL_EXTERNAL", "URL_LOCAL", "URL_SEARCH",
    "MESSAGE_INBOX", "MESSAGE_DRAFT", "MESSAGE_SENT",
    "POPUP_NOTIFICATION", "DIALOG_BOX", "SHELL", "FORM_FIELD",
    "UNKNOWN_TARGET",
}
ALLOWED_INTENTS = {
    "COMPLY_TASK", "REFUSE_INJECTION", "DETECT_INJECTION", "RETRY",
    "ABANDON", "EXPLORE", "UNKNOWN_INTENT",
}

# Each ground-truth vector should produce at least one step with this target
# tag if the agent observed the injection vector at all.
EXPECTED_TARGET_FOR_VECTOR = {
    "desktop_notification": {"POPUP_NOTIFICATION"},
    "website": {"APP_CHROME", "URL_EXTERNAL", "URL_LOCAL"},
    "libreoffice_writer": {"APP_LIBREOFFICE_WRITER", "FILE_DOC"},
    "thunderbird_mail_draft": {"APP_THUNDERBIRD", "MESSAGE_DRAFT"},
    "thunderbird_mail_received": {"APP_THUNDERBIRD", "MESSAGE_INBOX"},
    "vs_code": {"APP_VS_CODE", "FILE_CODE", "FILE_TEXT"},
}


def main() -> None:
    print(f"Loading traces from {L0_RESULTS} ...")
    traces = load_all_traces(L0_RESULTS)
    print(f"  Loaded {len(traces)} traces.\n")

    by_vec = defaultdict(list)
    for t in traces:
        by_vec[t.gt.vector].append(t)

    sample = []
    for vec, ts in sorted(by_vec.items()):
        sample.append(ts[0])
    print(f"Validation sample: {len(sample)} traces (1 per vector).")
    for t in sample:
        print(f"  - {t.gt.vector:<28} {t.trace_id[:60]}...  ({len(t.steps)} steps)")
    print()

    l2 = L2Semantic()
    meter = PrivacyLeakageMeter()  # for BLEU-2

    v1_total_steps = 0
    v1_failed_steps = 0
    v2_violations: list[str] = []
    v3_results: list[tuple[str, bool, set]] = []
    v4_bleu: list[tuple[str, float]] = []

    for t in sample:
        t0 = time.time()
        print(f"\n[L2] {t.gt.vector} / {t.trace_id[:50]}... ({len(t.steps)} steps)")
        try:
            abstracted = l2.apply(t)
        except Exception as e:
            print(f"  EXCEPTION during L2 apply: {e!r}")
            continue
        elapsed = time.time() - t0
        print(f"  L2 elapsed: {elapsed:.1f}s ({elapsed/max(1,len(t.steps)):.2f}s/step)")

        # V1: parse failure rate
        n_steps = len(abstracted.steps)
        n_failed = sum(
            1 for s in abstracted.steps if s.a11y_tree == "[L2_ABSTRACTION_FAILED]"
        )
        v1_total_steps += n_steps
        v1_failed_steps += n_failed
        if n_failed:
            print(f"  V1 parse failures: {n_failed}/{n_steps}")

        # V2: schema conformance
        observed_targets: set[str] = set()
        for s in abstracted.steps:
            intent = s.response
            if intent not in ALLOWED_INTENTS:
                v2_violations.append(
                    f"{t.gt.vector} intent={intent!r} not in schema"
                )
            for a in s.actions:
                # actions encoded as "ACTION -> TARGET"
                parts = a.split(" -> ")
                if len(parts) != 2:
                    v2_violations.append(f"{t.gt.vector} malformed action: {a!r}")
                    continue
                act, tgt = parts
                if act not in ALLOWED_ACTIONS:
                    v2_violations.append(f"{t.gt.vector} action={act!r} not in schema")
                if tgt not in ALLOWED_TARGETS:
                    v2_violations.append(f"{t.gt.vector} target={tgt!r} not in schema")
                observed_targets.add(tgt)

        # V3: source-region preservation
        expected = EXPECTED_TARGET_FOR_VECTOR.get(t.gt.vector, set())
        preserved = bool(expected & observed_targets)
        v3_results.append((t.gt.vector, preserved, observed_targets))
        print(f"  V3 source signal: expected one of {expected}, observed targets {sorted(observed_targets)} → "
              f"{'PRESERVED' if preserved else 'MISSING'}")

        # V4: BLEU-2 compression
        bleu = meter.m2_bleu2(meter._flatten(t), meter._flatten(abstracted))
        v4_bleu.append((t.gt.vector, bleu))
        print(f"  V4 BLEU-2: {bleu:.3f}  (lower is more compression)")

    # ---- summary ----
    print("\n" + "=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    v1_rate = (v1_failed_steps / v1_total_steps) if v1_total_steps else 0.0
    print(f"V1 parse failure: {v1_failed_steps}/{v1_total_steps} "
          f"({100*v1_rate:.1f}%)  threshold: <5%  "
          f"{'PASS' if v1_rate < 0.05 else 'FAIL'}")

    print(f"V2 schema drift  : {len(v2_violations)} violations  "
          f"threshold: 0  "
          f"{'PASS' if not v2_violations else 'FAIL'}")
    for v in v2_violations[:8]:
        print(f"   - {v}")
    if len(v2_violations) > 8:
        print(f"   ... and {len(v2_violations)-8} more")

    print(f"V3 source signal:")
    n_preserved = sum(1 for _, p, _ in v3_results if p)
    print(f"  preserved : {n_preserved}/{len(v3_results)}  "
          f"threshold: ALL  "
          f"{'PASS' if n_preserved == len(v3_results) else 'FAIL'}")
    for vec, pres, tgts in v3_results:
        if not pres:
            print(f"   - {vec}: MISSING (saw {sorted(tgts)})")

    if v4_bleu:
        mean_bleu = sum(b for _, b in v4_bleu) / len(v4_bleu)
        max_bleu = max(b for _, b in v4_bleu)
        print(f"V4 BLEU-2       : mean={mean_bleu:.3f}, max={max_bleu:.3f}  "
              f"threshold: <0.30  "
              f"{'PASS' if max_bleu < 0.30 else 'FAIL'}")
        for vec, b in v4_bleu:
            print(f"   - {vec:<28} {b:.3f}")

    print()
    print(f"L2 op stats: {l2.stats}")


if __name__ == "__main__":
    main()
