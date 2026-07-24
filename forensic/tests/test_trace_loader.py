"""Unit tests for trace_loader against the dry-run artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from forensic.trace_loader import (
    TRACE_DIR_PATTERN,
    Trace,
    find_trace_dirs,
    load_all_traces,
    load_trace,
)


DRY_RUN_TRACE = (
    REPO_ROOT
    / "test_results"
    / "pyautogui"
    / "screenshot_a11y_tree"
    / "gpt-4o-mini"
    / "chrome"
    / "2ad9387a-65d8-4e33-ad5b-7580065a27ca__inject__website__stop_task"
)


def test_regex_uuid_base_task():
    name = "2ad9387a-65d8-4e33-ad5b-7580065a27ca__inject__website__stop_task"
    m = TRACE_DIR_PATTERN.match(name)
    assert m is not None
    assert m.group("base_task") == "2ad9387a-65d8-4e33-ad5b-7580065a27ca"
    assert m.group("rest") == "website__stop_task"


def test_regex_underscore_prefix_base_task():
    name = "__injected_email__inject__thunderbird_mail_received__stop_task"
    m = TRACE_DIR_PATTERN.match(name)
    assert m is not None
    assert m.group("base_task") == "__injected_email"
    assert m.group("rest") == "thunderbird_mail_received__stop_task"


def test_load_dry_run_trace():
    assert DRY_RUN_TRACE.exists(), f"Dry-run trace missing at {DRY_RUN_TRACE}"
    trace = load_trace(DRY_RUN_TRACE)
    assert isinstance(trace, Trace)
    assert trace.trace_id.endswith("__inject__website__stop_task")
    assert trace.gt.base_task_id == "2ad9387a-65d8-4e33-ad5b-7580065a27ca"
    assert trace.gt.category == "chrome"
    assert trace.gt.vector == "website"
    assert trace.gt.goal == "stop_task"
    assert "Favorites" in trace.instruction
    assert trace.jailbreak is False
    assert len(trace.steps) == 3
    assert all(isinstance(s.actions, list) for s in trace.steps)
    assert trace.gt.candidate_goals
    assert trace.params.get("model") == "gpt-4o-mini"


def test_find_trace_dirs_on_dry_run_results():
    results_root = REPO_ROOT / "test_results"
    if not results_root.exists():
        return
    dirs = find_trace_dirs(results_root)
    assert any(d.name.endswith("__inject__website__stop_task") for d in dirs)


def test_load_all_traces_smoke():
    results_root = REPO_ROOT / "test_results"
    if not results_root.exists():
        return
    traces = load_all_traces(results_root)
    assert len(traces) >= 1
    assert all(t.gt.vector for t in traces)


if __name__ == "__main__":
    test_regex_uuid_base_task()
    print("ok test_regex_uuid_base_task")
    test_regex_underscore_prefix_base_task()
    print("ok test_regex_underscore_prefix_base_task")
    test_load_dry_run_trace()
    print("ok test_load_dry_run_trace")
    test_find_trace_dirs_on_dry_run_results()
    print("ok test_find_trace_dirs_on_dry_run_results")
    test_load_all_traces_smoke()
    print("ok test_load_all_traces_smoke")

    trace = load_trace(DRY_RUN_TRACE)
    print()
    print(f"=== Loaded trace: {trace.trace_id} ===")
    print(f"  category        = {trace.gt.category}")
    print(f"  base_task_id    = {trace.gt.base_task_id}")
    print(f"  vector          = {trace.gt.vector}")
    print(f"  goal            = {trace.gt.goal}")
    print(f"  candidate_goals = {trace.gt.candidate_goals}")
    print(f"  instruction     = {trace.instruction[:80]}...")
    print(f"  jailbreak       = {trace.jailbreak}")
    print(f"  steps           = {len(trace.steps)}")
    print(f"  final_caption?  = {trace.final_caption is not None}")
    print(f"  judge_verdict?  = {trace.judge_verdict is not None}")
    print(f"  injection (60ch)= {trace.gt.injection_content[:60]}...")
