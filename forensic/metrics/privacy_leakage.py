"""Privacy leakage metrics for abstracted traces (lower = more private).

  M1 (PII recall): |PII(abstracted) ∩ PII(raw)| / |PII(raw)|  (0 if raw has none).
  M2 (BLEU-2): bigram BLEU between raw and abstracted text.

Operates on a text blob or a whole Trace (text fields concatenated).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from nltk.translate.bleu_score import SmoothingFunction, sentence_bleu

from forensic.trace_loader import Trace


@dataclass
class LeakageResult:
    pii_recall: float          # M1, in [0, 1]
    bleu2: float               # M2, in [0, 1]
    n_pii_in_raw: int          # |P0|
    n_pii_intersect: int       # |P_i ∩ P0|
    n_tokens_raw: int
    n_tokens_abstracted: int


class PrivacyLeakageMeter:
    """Privacy leakage meter.

    `entities` controls *which entity types are counted as PII* in M1.
    Passing the same list as the L1 operator's target entities makes M1
    comparable: it measures only the PII that the abstraction operator was
    supposed to mask. Passing None (default) counts all 17 Presidio
    recognizers, which is dominated by false positives on agent-trace text
    (DATE_TIME on coordinates, PERSON on UI tokens, etc.).
    """

    def __init__(
        self,
        *,
        score_threshold: float = 0.4,
        entities: tuple[str, ...] | None = None,
    ) -> None:
        self.score_threshold = score_threshold
        self.entities = entities

    @cached_property
    def _analyzer(self):  # type: ignore[no-untyped-def]
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        for lang_code in analyzer.nlp_engine.nlp:
            analyzer.nlp_engine.nlp[lang_code].max_length = 10_000_000
        return analyzer

    # Cap text passed to spaCy; longer traces are head-truncated to this length.
    _SPACY_MAX_CHARS = 500_000

    def _detect_pii_strings(self, text: str) -> set[str]:
        if not text:
            return set()
        if len(text) > self._SPACY_MAX_CHARS:
            text = text[:self._SPACY_MAX_CHARS]
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=list(self.entities) if self.entities else None,
            score_threshold=self.score_threshold,
        )
        return {text[r.start:r.end] for r in results}

    def m1_pii_recall(self, raw: str, abstracted: str) -> tuple[float, int, int]:
        p0 = self._detect_pii_strings(raw)
        if not p0:
            return 0.0, 0, 0
        pi = self._detect_pii_strings(abstracted)
        intersect = p0 & pi
        return len(intersect) / len(p0), len(p0), len(intersect)

    def m2_bleu2(self, raw: str, abstracted: str) -> float:
        ref = raw.split()
        hyp = abstracted.split()
        if not ref or not hyp:
            return 0.0
        smooth = SmoothingFunction().method1
        return sentence_bleu(
            [ref], hyp, weights=(0.5, 0.5, 0, 0), smoothing_function=smooth
        )

    def measure_text(self, raw: str, abstracted: str) -> LeakageResult:
        recall, n_p0, n_inter = self.m1_pii_recall(raw, abstracted)
        bleu = self.m2_bleu2(raw, abstracted)
        return LeakageResult(
            pii_recall=recall,
            bleu2=bleu,
            n_pii_in_raw=n_p0,
            n_pii_intersect=n_inter,
            n_tokens_raw=len(raw.split()),
            n_tokens_abstracted=len(abstracted.split()),
        )

    def measure_trace(self, raw: Trace, abstracted: Trace) -> LeakageResult:
        raw_text = self._flatten(raw)
        abs_text = self._flatten(abstracted)
        return self.measure_text(raw_text, abs_text)

    @staticmethod
    def _flatten(t: Trace) -> str:
        parts: list[str] = [t.instruction or ""]
        if t.final_caption:
            parts.append(t.final_caption)
        for s in t.steps:
            parts.append(s.a11y_tree or "")
            parts.append(s.response or "")
            parts.extend(s.actions or [])
        return "\n".join(p for p in parts if p)
