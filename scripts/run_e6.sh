#!/usr/bin/env bash
# scripts/run_e6.sh — E6 collection runbook for DFRWS APAC 2026 submission
#
# Collects the two OS-HARM incident types not yet in results/osharm_ipi_L0/:
#   - test_misuse.json       (50 traces, --jailbreak)
#   - test_misbehavior.json  (50 traces, no flag)
# under the same gpt-4o-mini + screenshot_a11y_tree + max_steps=15 config
# used for IPI, so cross-type comparison is hyperparam-controlled.
#
# Inline judge runs per-trace inside run.py (gpt-4.1 / aer / v3), writing
#   <trace_dir>/judgment/gpt-4.1/aer/v3/judgment.json
# Each completed trajectory also writes result.txt — used by both run.py's
# resume logic and the checkpoint command below.
#
# Total: ~10h serial single-VM, ~$10 API spend (estimate).
# Abort threshold: if checkpoint reports >ABORT_THRESHOLD/100 missing
# trajectories, recommend switching to scenario B (drop RQ4 to §7).
#
# Resumability: run.py skips trace dirs containing result.txt, so any
# subcommand can be re-run safely after VM crash / API hiccup.
#
# Prereqs:
#   - VMware Fusion VM at $VM_PATH is shut down (run.py boots it itself)
#   - conda env osworld active (or python on PATH has run.py's deps)
#   - OPENAI_API_KEY exported (agent + judge both use OpenAI models)

set -euo pipefail

# === Config (override via env vars) =========================================
VM_PATH="${VM_PATH:-/Users/alexmac/Documents/OSWorld-osharm/vmware_vm_data/Ubuntu0/Ubuntu0.vmx}"
MODEL="${MODEL:-gpt-4o-mini}"
OBSERVATION_TYPE="${OBSERVATION_TYPE:-screenshot_a11y_tree}"
MAX_STEPS="${MAX_STEPS:-15}"
JUDGE_MODEL="${JUDGE_MODEL:-gpt-4.1}"
JUDGE_TYPE="${JUDGE_TYPE:-aer}"
SYS_PROMPT_VERSION="${SYS_PROMPT_VERSION:-v3}"
HEADLESS_FLAG="${HEADLESS_FLAG:---headless}"

MISUSE_DIR="${MISUSE_DIR:-./results/osharm_misuse_L0}"
MISBEHAVIOR_DIR="${MISBEHAVIOR_DIR:-./results/osharm_misbehavior_L0}"

ABORT_THRESHOLD="${ABORT_THRESHOLD:-30}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# === Pre-flight =============================================================

preflight() {
    local fail=0
    if [ ! -f "$VM_PATH" ]; then
        echo "ERROR: VM_PATH not found: $VM_PATH" >&2
        fail=1
    fi
    if [ -z "${OPENAI_API_KEY:-}" ]; then
        echo "ERROR: OPENAI_API_KEY not set (needed for agent + judge)" >&2
        fail=1
    fi
    if [ ! -f "evaluation_examples/test_misuse.json" ] || [ ! -f "evaluation_examples/test_misbehavior.json" ]; then
        echo "ERROR: evaluation_examples/test_{misuse,misbehavior}.json missing" >&2
        fail=1
    fi
    if ! python -c "import desktop_env, mm_agents, judge" 2>/dev/null; then
        echo "ERROR: python env missing run.py deps — activate conda env osworld?" >&2
        fail=1
    fi
    [ "$fail" -eq 0 ] || exit 1
}

# === Phase commands =========================================================

collect_misuse() {
    preflight
    echo ">>> [$(date +'%F %T')] Misuse 50 collection start (~5h serial, ~\$5)"
    python run.py \
        --path_to_vm "$VM_PATH" \
        $HEADLESS_FLAG \
        --observation_type "$OBSERVATION_TYPE" \
        --test_all_meta_path evaluation_examples/test_misuse.json \
        --jailbreak \
        --model "$MODEL" \
        --max_steps "$MAX_STEPS" \
        --judge_model "$JUDGE_MODEL" \
        --judge_type "$JUDGE_TYPE" \
        --sys_prompt_version "$SYS_PROMPT_VERSION" \
        --result_dir "$MISUSE_DIR"
    echo ">>> [$(date +'%F %T')] Misuse done"
}

collect_misbehavior() {
    preflight
    echo ">>> [$(date +'%F %T')] Misbehavior 50 collection start (~5h serial, ~\$5)"
    python run.py \
        --path_to_vm "$VM_PATH" \
        $HEADLESS_FLAG \
        --observation_type "$OBSERVATION_TYPE" \
        --test_all_meta_path evaluation_examples/test_misbehavior.json \
        --model "$MODEL" \
        --max_steps "$MAX_STEPS" \
        --judge_model "$JUDGE_MODEL" \
        --judge_type "$JUDGE_TYPE" \
        --sys_prompt_version "$SYS_PROMPT_VERSION" \
        --result_dir "$MISBEHAVIOR_DIR"
    echo ">>> [$(date +'%F %T')] Misbehavior done"
}

checkpoint() {
    local misuse_done=0 misbehavior_done=0 misuse_judge=0 misbehavior_judge=0
    [ -d "$MISUSE_DIR" ]      && misuse_done=$(find "$MISUSE_DIR"      -name result.txt   2>/dev/null | wc -l | tr -d ' ')
    [ -d "$MISBEHAVIOR_DIR" ] && misbehavior_done=$(find "$MISBEHAVIOR_DIR" -name result.txt   2>/dev/null | wc -l | tr -d ' ')
    [ -d "$MISUSE_DIR" ]      && misuse_judge=$(find "$MISUSE_DIR"      -name judgment.json 2>/dev/null | wc -l | tr -d ' ')
    [ -d "$MISBEHAVIOR_DIR" ] && misbehavior_judge=$(find "$MISBEHAVIOR_DIR" -name judgment.json 2>/dev/null | wc -l | tr -d ' ')

    local total_done=$((misuse_done + misbehavior_done))
    local total_judge=$((misuse_judge + misbehavior_judge))
    local missing=$((100 - total_done))

    cat <<EOF
=== E6 collection checkpoint ($(date +'%F %T')) ===
  Misuse:       $misuse_done / 50 trajectories complete   ($misuse_judge judged)
  Misbehavior:  $misbehavior_done / 50 trajectories complete   ($misbehavior_judge judged)
  Total:        $total_done / 100   ($total_judge judged)
  Missing:      $missing  (abort threshold: $ABORT_THRESHOLD)
EOF

    if [ "$missing" -gt "$ABORT_THRESHOLD" ]; then
        echo "!!! ABORT THRESHOLD HIT ($missing > $ABORT_THRESHOLD). Recommend scenario B: drop RQ4 to §7 future work."
        return 1
    fi
    echo "OK — within tolerance. Proceed with A1/A3 decision and downstream analysis."
}

# === Dispatcher =============================================================

usage() {
    cat <<EOF
Usage: $0 <command>

Commands:
  collect-misuse        Misuse 50 collection (--jailbreak)        ~5h, ~\$5
  collect-misbehavior   Misbehavior 50 collection (no flag)        ~5h, ~\$5
  collect-all           Both, back-to-back                          ~10h, ~\$10
  checkpoint            Report counts; exit 1 if >${ABORT_THRESHOLD}/100 missing
  all                   collect-all + checkpoint

Env overrides (current values shown):
  VM_PATH             = $VM_PATH
  MODEL               = $MODEL
  OBSERVATION_TYPE    = $OBSERVATION_TYPE
  MAX_STEPS           = $MAX_STEPS
  JUDGE_MODEL         = $JUDGE_MODEL  ($JUDGE_TYPE / $SYS_PROMPT_VERSION)
  HEADLESS_FLAG       = $HEADLESS_FLAG  (set to "" to disable)
  MISUSE_DIR          = $MISUSE_DIR
  MISBEHAVIOR_DIR     = $MISBEHAVIOR_DIR
  ABORT_THRESHOLD     = $ABORT_THRESHOLD

Output layout (per category):
  <result_dir>/pyautogui/$OBSERVATION_TYPE/${MODEL}[_jailbreak]/<domain>/<example_id>/
    ├ better_log.json
    ├ messages.json
    ├ traj.jsonl
    ├ result.txt                                  (completion marker)
    ├ recording.mp4
    └ judgment/${JUDGE_MODEL}/${JUDGE_TYPE}/${SYS_PROMPT_VERSION}/judgment.json

Notes:
  - Re-runs are idempotent: run.py skips dirs containing result.txt.
  - Misuse dir uses model_name = "${MODEL}_jailbreak" (run.py appends suffix when --jailbreak is set).
  - Inline judge runs per-trace inside run.py; no separate judge phase needed.
  - Caveat: if the inline judge raises mid-batch, run.py exits — re-run the subcommand to resume.
  - After collection: decide A1 (saliency-style RQ4) vs A3 (privacy-only RQ4) before writing analysis pipelines.
EOF
}

case "${1:-help}" in
    collect-misuse)       collect_misuse ;;
    collect-misbehavior)  collect_misbehavior ;;
    collect-all)
        collect_misuse
        collect_misbehavior
        ;;
    all)
        collect_misuse
        collect_misbehavior
        checkpoint
        ;;
    checkpoint)           checkpoint ;;
    -h|--help|help|*)     usage ;;
esac
