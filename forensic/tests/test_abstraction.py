"""Unit tests for abstraction operators (L0 identity, L1 PII)."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.abstraction import L0Identity, L1PII
from forensic.trace_loader import load_trace

DRY_RUN_TRACE = (
    REPO_ROOT
    / "test_results"
    / "pyautogui"
    / "screenshot_a11y_tree"
    / "gpt-4o-mini"
    / "chrome"
    / "2ad9387a-65d8-4e33-ad5b-7580065a27ca__inject__website__stop_task"
)


def test_l0_is_identity_on_text_and_trace():
    op = L0Identity()
    assert op.name == "L0"
    assert op.level == 0
    sample = "Email me at alice@example.com about phone +1-555-867-5309."
    assert op.abstract_text(sample) == sample

    if not DRY_RUN_TRACE.exists():
        return
    original = load_trace(DRY_RUN_TRACE)
    abstracted = op.apply(original)
    assert abstracted is not original
    assert abstracted.instruction == original.instruction
    assert len(abstracted.steps) == len(original.steps)
    for a, o in zip(abstracted.steps, original.steps):
        assert a.a11y_tree == o.a11y_tree
        assert a.response == o.response
        assert a.actions == o.actions
    assert abstracted.gt == original.gt


def test_l1_masks_pii_entities():
    """Verify L1 masks reliably-detected PII types (email, credit card, IP).

    Note: Presidio's SSN/phone recognizers use strict validation
    (real-area-code, valid-issuing-block) that rejects fictional test fixtures,
    so we don't assert on those here.
    """
    try:
        op = L1PII()
    except ImportError:
        print("SKIP: presidio not installed")
        return
    masked = op.abstract_text(
        "Contact alice@example.com. Card 4111-1111-1111-1111. Server 192.168.1.42."
    )
    assert "alice@example.com" not in masked
    assert "<EMAIL_ADDRESS>" in masked
    assert "4111-1111-1111-1111" not in masked
    assert "<CREDIT_CARD>" in masked
    assert "192.168.1.42" not in masked
    assert "<IP_ADDRESS>" in masked


def test_l1_preserves_non_pii_and_ground_truth():
    try:
        op = L1PII()
    except ImportError:
        print("SKIP: presidio not installed")
        return

    benign = "Open Chrome and create a new folder."
    assert op.abstract_text(benign) == benign

    if not DRY_RUN_TRACE.exists():
        return
    original = load_trace(DRY_RUN_TRACE)
    abstracted = op.apply(original)
    assert abstracted.gt == original.gt
    assert abstracted.jailbreak == original.jailbreak
    assert len(abstracted.steps) == len(original.steps)


if __name__ == "__main__":
    test_l0_is_identity_on_text_and_trace()
    print("ok test_l0_is_identity_on_text_and_trace")
    test_l1_masks_pii_entities()
    print("ok test_l1_masks_pii_entities")
    test_l1_preserves_non_pii_and_ground_truth()
    print("ok test_l1_preserves_non_pii_and_ground_truth")
