"""L0 (identity) abstraction — passes the trace through unchanged.

Serves as the upper-bound baseline for attribution accuracy and the lower-bound
baseline for privacy preservation (no privacy gain).
"""

from __future__ import annotations

from forensic.abstraction.base import AbstractionOperator


class L0Identity(AbstractionOperator):
    name = "L0"
    level = 0

    def abstract_text(self, text: str) -> str:
        return text
