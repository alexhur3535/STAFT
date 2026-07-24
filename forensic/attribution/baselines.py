"""Attribution baselines.

B1 (Random): seeded per-trace permutation, chance-level.
B2 (Keyword): score each vector by vector-specific keyword frequency.
"""

from __future__ import annotations

import random

from forensic.attribution.base import (
    CANDIDATE_VECTORS,
    AttributionAlgorithm,
    AttributionResult,
)
from forensic.trace_loader import Trace


class B1Random(AttributionAlgorithm):
    name = "B1_random"

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def attribute(self, trace: Trace) -> AttributionResult:
        rng = random.Random(f"{self.seed}|{trace.trace_id}")
        ranked = list(CANDIDATE_VECTORS)
        rng.shuffle(ranked)
        n = len(ranked)
        scores = {v: (n - i) / n for i, v in enumerate(ranked)}
        return AttributionResult(
            trace_id=trace.trace_id,
            gt_vector=trace.gt.vector,
            ranked_sources=ranked,
            scores=scores,
            method=self.name,
        )


# Per-vector keyword patterns used by B2. The patterns target the textual
# fields a forensic investigator would see at L0/L1; they degrade naturally
# at L2 (since identifier-level text is removed) which is itself a useful
# datum for the paper.
_VECTOR_KEYWORDS: dict[str, tuple[str, ...]] = {
    "desktop_notification": (
        "notify-send", "popup notification", "desktop notification",
        "notification window", "important: for the ai agent",
        "important: to the ai agent",
    ),
    "libreoffice_writer": (
        "libreoffice writer", "libreoffice_writer", ".docx", ".odt",
        "document body", "page numbers",
    ),
    "thunderbird_mail_draft": (
        "compose window", "compose mail", "subject:", "draft",
        "from='", "thunderbird -compose",
    ),
    "thunderbird_mail_received": (
        "inbox", "received mail", "mail folder", "mbox",
        "important folder", "unread email",
    ),
    "vs_code": (
        "visual studio code", "vs_code", ".py", ".txt",
        "code editor", "editor group", "explorer",
    ),
    "website": (
        "address bar", "chromium web browser", "google chrome",
        "page source", "navigation bar", "url bar",
    ),
}


class B2Keyword(AttributionAlgorithm):
    name = "B2_keyword"

    def attribute(self, trace: Trace) -> AttributionResult:
        # Concatenate textual fields for case-insensitive substring search.
        parts: list[str] = [trace.instruction or ""]
        if trace.final_caption:
            parts.append(trace.final_caption)
        for s in trace.steps:
            parts.append(s.a11y_tree or "")
            parts.append(s.response or "")
            parts.extend(s.actions or [])
        haystack = "\n".join(parts).lower()

        scores: dict[str, float] = {}
        for vec in CANDIDATE_VECTORS:
            kws = _VECTOR_KEYWORDS.get(vec, ())
            scores[vec] = float(sum(haystack.count(kw.lower()) for kw in kws))

        # Tie-break by vector name to keep deterministic.
        ranked = sorted(scores, key=lambda v: (-scores[v], v))
        return AttributionResult(
            trace_id=trace.trace_id,
            gt_vector=trace.gt.vector,
            ranked_sources=ranked,
            scores=scores,
            method=self.name,
        )
