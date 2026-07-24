"""Abstraction operator interface: A: Trace -> Trace, a lossy privacy-preserving view.

Operators must be deterministic given (input, seed), must not mutate the input,
and must preserve `Trace.gt` unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import replace
from typing import Iterable

from forensic.trace_loader import Trace, TraceStep


class AbstractionOperator(ABC):
    """Base class for abstraction operators (L0, L1, L2)."""

    name: str = ""
    level: int = -1

    @abstractmethod
    def abstract_text(self, text: str) -> str:
        """Abstract a single text blob. Operator-specific implementation."""

    def apply(self, trace: Trace) -> Trace:
        """Return a new Trace with all abstractable textual fields transformed."""
        new_steps: list[TraceStep] = []
        for step in trace.steps:
            new_steps.append(
                TraceStep(
                    a11y_tree=self.abstract_text(step.a11y_tree),
                    screenshot_file=step.screenshot_file,
                    response=self.abstract_text(step.response),
                    actions=[self.abstract_text(a) for a in step.actions],
                )
            )
        return replace(
            trace,
            instruction=self.abstract_text(trace.instruction),
            steps=new_steps,
            final_caption=(
                self.abstract_text(trace.final_caption)
                if trace.final_caption is not None
                else None
            ),
            gt=deepcopy(trace.gt),
        )

    def apply_many(self, traces: Iterable[Trace]) -> list[Trace]:
        return [self.apply(t) for t in traces]
