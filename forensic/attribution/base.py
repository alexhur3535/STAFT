"""Attribution algorithm interface.

Each algorithm ranks the 6 OS-HARM IPI injection vectors (`CANDIDATE_VECTORS`)
by predicted influence on the agent's behavior, returning an `AttributionResult`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from forensic.trace_loader import Trace

CANDIDATE_VECTORS: tuple[str, ...] = (
    "desktop_notification",
    "libreoffice_writer",
    "thunderbird_mail_draft",
    "thunderbird_mail_received",
    "vs_code",
    "website",
)


@dataclass
class AttributionResult:
    trace_id: str
    gt_vector: str
    ranked_sources: list[str]        # by descending score
    scores: dict[str, float]
    method: str                      # e.g. "B1_random", "B2_keyword", "LOO_LLM"

    @property
    def top1(self) -> str:
        return self.ranked_sources[0] if self.ranked_sources else ""

    @property
    def top1_correct(self) -> bool:
        return self.top1 == self.gt_vector

    def topk_correct(self, k: int) -> bool:
        return self.gt_vector in self.ranked_sources[:k]

    @property
    def rank_of_gt(self) -> int:
        try:
            return self.ranked_sources.index(self.gt_vector) + 1
        except ValueError:
            return len(self.ranked_sources) + 1

    @property
    def reciprocal_rank(self) -> float:
        return 1.0 / self.rank_of_gt


class AttributionAlgorithm(ABC):
    name: str = ""

    @abstractmethod
    def attribute(self, trace: Trace) -> AttributionResult:
        ...

    def attribute_many(self, traces: list[Trace]) -> list[AttributionResult]:
        return [self.attribute(t) for t in traces]
