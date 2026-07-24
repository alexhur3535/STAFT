"""Parse an OS-HARM trace directory into a Trace dataclass.

Single point of contact for the better_log.json schema. Covers IPI
(`__inject__<vec>__<goal>` dirs), misuse (`--jailbreak`), and misbehavior;
GroundTruth.vector/goal/injection_content/candidate_goals are set for IPI only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


TRACE_DIR_PATTERN = re.compile(r"^(?P<base_task>.+?)__inject__(?P<rest>.+)$")

CATEGORY_PARENTS = {
    "chrome",
    "libreoffice_writer",
    "libreoffice_calc",
    "libreoffice_impress",
    "gimp",
    "multi_apps",
    "os",
    "thunderbird",
    "vlc",
    "vs_code",
}

INCIDENT_TYPES = ("ipi", "misuse", "misbehavior")


@dataclass
class TraceStep:
    a11y_tree: str
    screenshot_file: str
    response: str
    actions: list[str]


@dataclass
class GroundTruth:
    base_task_id: str
    category: str
    incident_type: str = "ipi"            # "ipi" | "misuse" | "misbehavior"
    vector: str | None = None             # IPI injection type; None otherwise
    goal: str | None = None               # IPI injection goal_id; None otherwise
    injection_content: str = ""           # IPI injection content; "" otherwise
    candidate_goals: list[str] = field(default_factory=list)


@dataclass
class Trace:
    trace_id: str
    trace_dir: Path
    instruction: str
    jailbreak: bool
    steps: list[TraceStep]
    final_caption: str | None
    judge_verdict: dict[str, Any] | None
    gt: GroundTruth
    params: dict[str, Any] = field(default_factory=dict)


def _infer_category(trace_dir: Path) -> str:
    for parent in trace_dir.parents:
        if parent.name in CATEGORY_PARENTS:
            return parent.name
    raise ValueError(f"Could not infer OS-HARM category from path: {trace_dir}")


def _infer_incident_type(injection: Any, jailbreak: bool) -> str:
    if injection is not None:
        return "ipi"
    if jailbreak:
        return "misuse"
    return "misbehavior"


def _load_final_caption(trace_dir: Path) -> str | None:
    candidates = list(trace_dir.glob("*.last_screenshot_caption.json"))
    if not candidates:
        return None
    with candidates[0].open() as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        for key in ("caption", "content", "text"):
            if key in payload:
                return payload[key]
        return json.dumps(payload)
    return str(payload)


def _load_judge_verdict(trace_dir: Path) -> dict[str, Any] | None:
    judge_dir = trace_dir / "judgment"
    if not judge_dir.exists():
        return None
    verdict: dict[str, Any] = {}
    for jf in judge_dir.rglob("*.json"):
        try:
            with jf.open() as f:
                verdict[jf.stem] = json.load(f)
        except json.JSONDecodeError:
            continue
    return verdict or None


def load_trace(trace_dir: Path, *, strict_cross_check: bool = True) -> Trace:
    """Parse one OS-HARM trace directory.

    `strict_cross_check` applies only to IPI traces: asserts that the dir name's
    __inject__ suffix matches `task.injection.type` and `task.injection.goal_id`
    from better_log.json. For misuse / misbehavior traces (injection is None),
    the cross-check is automatically skipped.
    """
    trace_dir = Path(trace_dir)
    log_path = trace_dir / "better_log.json"
    if not log_path.exists():
        raise FileNotFoundError(f"better_log.json not found in {trace_dir}")

    with log_path.open() as f:
        log = json.load(f)

    task = log["task"]
    injection = task.get("injection")
    jailbreak = bool(task.get("jailbreak", False))
    incident_type = _infer_incident_type(injection, jailbreak)

    if incident_type == "ipi":
        m = TRACE_DIR_PATTERN.match(trace_dir.name)
        if not m:
            raise ValueError(
                f"IPI trace dir name does not match __inject__ pattern: {trace_dir.name}"
            )
        base_task = m.group("base_task")
        suffix = m.group("rest")
        vector = injection["type"]
        goal = injection["goal_id"]
        if strict_cross_check:
            expected = f"{vector}__{goal}"
            if suffix != expected:
                raise AssertionError(
                    f"Dir suffix '{suffix}' != better_log injection '{expected}' "
                    f"(trace_dir={trace_dir.name})"
                )
        injection_content = injection.get("content", "")
        candidate_goals = list(injection.get("goals", []))
    else:
        base_task = trace_dir.name
        vector = None
        goal = None
        injection_content = ""
        candidate_goals = []

    steps = [
        TraceStep(
            a11y_tree=s.get("a11y_tree", ""),
            screenshot_file=s.get("screenshot_file", ""),
            response=s.get("response", ""),
            actions=s.get("actions", []) or [],
        )
        for s in log.get("steps", [])
    ]

    gt = GroundTruth(
        base_task_id=base_task,
        category=_infer_category(trace_dir),
        incident_type=incident_type,
        vector=vector,
        goal=goal,
        injection_content=injection_content,
        candidate_goals=candidate_goals,
    )

    return Trace(
        trace_id=trace_dir.name,
        trace_dir=trace_dir,
        instruction=task["instruction"],
        jailbreak=jailbreak,
        steps=steps,
        final_caption=_load_final_caption(trace_dir),
        judge_verdict=_load_judge_verdict(trace_dir),
        gt=gt,
        params=log.get("params", {}),
    )


def find_trace_dirs(
    results_root: Path,
    *,
    require_inject_suffix: bool = True,
) -> list[Path]:
    """Find trace dirs (those containing `better_log.json`).

    With `require_inject_suffix=True` (default, IPI backwards-compat), only
    dirs whose name contains `__inject__` are returned. Set to False for
    misuse / misbehavior collections, which use plain `<example_id>` names.
    """
    results_root = Path(results_root)
    if require_inject_suffix:
        candidates = list(results_root.rglob("*__inject__*"))
    else:
        candidates = [p.parent for p in results_root.rglob("better_log.json")]
    seen: set[Path] = set()
    out: list[Path] = []
    for d in candidates:
        if d in seen:
            continue
        seen.add(d)
        if d.is_dir() and (d / "better_log.json").exists():
            out.append(d)
    return sorted(out)


def load_all_traces(
    results_root: Path,
    *,
    strict_cross_check: bool = True,
    require_inject_suffix: bool = True,
) -> list[Trace]:
    return [
        load_trace(d, strict_cross_check=strict_cross_check)
        for d in find_trace_dirs(results_root, require_inject_suffix=require_inject_suffix)
    ]
