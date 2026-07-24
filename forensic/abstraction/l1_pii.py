"""L1 (PII masking) abstraction using Microsoft Presidio.

Replaces detected PII entity spans with `<{ENTITY_TYPE}>` placeholders, e.g.
`alice@example.com` -> `<EMAIL_ADDRESS>`. Entity types and recognizers come
from Presidio's default English recognizer registry.

Requires:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg
"""

from __future__ import annotations

from functools import cached_property

from forensic.abstraction.base import AbstractionOperator

DEFAULT_ENTITIES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_SSN",
    "US_PASSPORT",
    "CRYPTO",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
)


# DATE_TIME / PERSON / LOCATION / URL are excluded by default (high false-positive
# rates on trace content: coordinates, UI labels, code identifiers). Override via
# entities= to L1PII().


class L1PII(AbstractionOperator):
    name = "L1"
    level = 1

    def __init__(
        self,
        *,
        language: str = "en",
        entities: tuple[str, ...] = DEFAULT_ENTITIES,
        score_threshold: float = 0.4,
    ) -> None:
        self.language = language
        self.entities = entities
        self.score_threshold = score_threshold

    @cached_property
    def _analyzer(self):  # type: ignore[no-untyped-def]
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as e:
            raise ImportError(
                "L1PII requires presidio-analyzer. Install with:\n"
                "    pip install presidio-analyzer presidio-anonymizer\n"
                "    python -m spacy download en_core_web_lg"
            ) from e
        analyzer = AnalyzerEngine()
        # Some OS-HARM traces (misbehavior vs_code with full a11y trees over
        # 15 steps) exceed spaCy's default 1M-char limit. Bump generously.
        for lang_code in analyzer.nlp_engine.nlp:
            analyzer.nlp_engine.nlp[lang_code].max_length = 10_000_000
        return analyzer

    @cached_property
    def _anonymizer(self):  # type: ignore[no-untyped-def]
        from presidio_anonymizer import AnonymizerEngine

        return AnonymizerEngine()

    # Cap text passed to spaCy per call; PII in the tail beyond this is not redacted.
    _SPACY_MAX_CHARS = 30_000

    def abstract_text(self, text: str) -> str:
        if not text:
            return text
        if len(text) > self._SPACY_MAX_CHARS:
            head, tail = text[:self._SPACY_MAX_CHARS], text[self._SPACY_MAX_CHARS:]
            results = self._analyzer.analyze(
                text=head,
                language=self.language,
                entities=list(self.entities),
                score_threshold=self.score_threshold,
            )
            if not results:
                return text
            anonymized_head = self._anonymizer.anonymize(text=head, analyzer_results=results)
            return anonymized_head.text + tail
        results = self._analyzer.analyze(
            text=text,
            language=self.language,
            entities=list(self.entities),
            score_threshold=self.score_threshold,
        )
        if not results:
            return text
        anonymized = self._anonymizer.anonymize(text=text, analyzer_results=results)
        return anonymized.text
