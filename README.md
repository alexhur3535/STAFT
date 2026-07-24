# STAFT: Privacy-Preserving Semantic Trace Abstraction for Forensic Triage of Personal AI Agent Incidents

STAFT (**S**emantic **T**race **A**bstraction for **F**orensic **T**riage) is a
privacy-preserving triage layer for incidents involving personal AI agents.
Raw agent execution traces are transformed into a compact sequence of
structured **⟨action × target × intent⟩** tags that preserve behavior-level
incident flow while removing surface content (message bodies, file names, URLs,
coordinates, raw UI text). The abstracted artifact stays cryptographically
linked to the sealed raw trace for chain of custody, and serves as a
low-authorization working view for incident triage and cross-team review.

Evaluating **150 OS-HARM traces** (50 each across indirect prompt injection,
deliberate misuse, and model misbehavior), we show that conventional PII
masking provides little protection (M1 = 0.000, M2 = 0.998), whereas STAFT
compresses traces by **98.5%** with **zero** surface overlap, yet keeps the
ground-truth source in the **top three for 94%** of injection traces.

> This repository accompanies the paper *"STAFT: Privacy-Preserving Semantic
> Trace Abstraction for Forensic Triage of Personal AI Agent Incidents"*
> (DFRWS APAC 2026, under review). It releases the forensic framework, the L2
> abstraction prompt schema, and the per-trace privacy and probe artifacts.

---

## Framework overview

![STAFT framework overview](figs/overall_framework.png)

An LLM agent runs OS-HARM tasks in an OSWorld Ubuntu VM, producing raw
execution traces (**L0**). STAFT progressively abstracts each trace through
Presidio-based PII masking (**L1**) and semantic-tag abstraction (**L2**),
where every step becomes a structured `⟨action × target × intent⟩` envelope.
The L2 artifact is the default **low-authorization** review surface for
privacy-preserving forensic triage — inspect the semantic timeline, rank
suspicious source regions, and escalate to L1/L0 only when justified — while
the sealed raw trace stays under **SHA-256 hash-linked** chain-of-custody.

---

## Abstraction levels

| Level  | Name                          | Operator     | Source file                          |
|--------|-------------------------------|--------------|--------------------------------------|
| **L0** | raw (identity)                | `L0Identity` | `forensic/abstraction/l0_identity.py`|
| **L1** | Presidio PII masking          | `L1PII`      | `forensic/abstraction/l1_pii.py`     |
| **L2** | semantic tagging (LLM-tagger) | `L2Semantic` | `forensic/abstraction/l2_semantic.py`|

The L2 `⟨action × target × intent⟩` schema and concrete before/after examples
are documented in [`docs/ABSTRACTION_LEVELS.md`](docs/ABSTRACTION_LEVELS.md).

---

## Repository structure

```
STAFT/
├── forensic/                 # ★ STAFT framework (the core contribution)
│   ├── abstraction/          #   L0 / L1 / L2 abstraction operators
│   ├── attribution/          #   source-ranking probes: B1 random, B2 keyword, LOO-LLM
│   ├── metrics/              #   privacy metrics M1 (PII recall), M2 (BLEU-2), M3 (recovery)
│   ├── pipeline/             #   experiment runners (run_l1/l2_baseline, run_attribution)
│   ├── tests/                #   unit tests for the abstraction operators & loader
│   └── trace_loader.py       #   OS-HARM trace → Trace dataclass parser
├── results/                  # released artifacts (abstracted L2 traces + reports)
│   ├── l2_traces*.jsonl      #   the released L2 abstractions (IPI / misuse / misbehavior)
│   ├── *_report.json         #   per-experiment metric reports
│   └── osharm_*_L0/          #   raw traces — NOT committed (regenerate, see below)
├── docs/                     # L2 schema reference + OS-HARM account/proxy setup guides
│   ├── ABSTRACTION_LEVELS.md
│   ├── ACCOUNT_GUIDELINE.md
│   ├── PROXY_GUIDELINE.md
│   └── OSHARM_UPSTREAM_README.md
├── run.py, lib_run_single.py # OS-HARM / OSWorld agent runtime (trace collection)
├── mm_agents/, desktop_env/  #   "
├── judge/                    # OS-HARM safety/success judge
├── evaluation_examples/      # OS-HARM task definitions (test_injection/misuse/misbehavior.json)
├── scripts/                  # collection runbooks (run_e6.sh) + analysis notebooks
├── requirements.txt
└── pyproject.toml
```

The **raw L0 traces** (`results/osharm_*_L0/`, ~1.35 GB) are intentionally not
committed: they are the privacy-sensitive artifact STAFT is designed to
abstract away. The released **L2 traces** (`results/l2_traces*.jsonl`) and the
**metric reports** are sufficient to inspect every number in the paper, and the
raw traces can be regenerated from OS-HARM (see §6).

---

## 1. Environment setup

STAFT requires **Python ≥ 3.12**.

```bash
# Using conda (recommended)
conda create -n staft python=3.12 -y
conda activate staft

pip install -r requirements.txt

# Presidio's NER backend (required for L1 PII masking)
python -m spacy download en_core_web_lg

# NLTK tokenizer data (required for the M2 BLEU-2 metric)
python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab')"
```

If you only want to **reproduce the forensic analysis** from the released L2
traces (and not regenerate raw traces), group (A) of `requirements.txt` is
sufficient; the OS-HARM runtime dependencies in group (B) are only needed for
trace collection (§6).

---

## 2. Configure LLM

STAFT calls hosted models for the L2 tagger, the LOO-LLM probe, and the M3
adversary. Export the corresponding keys:

```bash
export OPENAI_API_KEY="sk-..."        # L2 tagger (gpt-4o-mini) + LOO-LLM probe + OS-HARM judge (gpt-4.1)
export ANTHROPIC_API_KEY="sk-ant-..." # M3 adversarial reconstructor (claude-haiku-4-5)
```

| Role                         | Model                         | Temp / seed |
|------------------------------|-------------------------------|-------------|
| Agent runtime (collection)   | `gpt-4o-mini`                 | 1.0         |
| L2 semantic tagger           | `gpt-4o-mini`                 | 0 / 42      |
| LOO-LLM source-ranking probe | `gpt-4o-mini`                 | 0 / 42      |
| M3 adversary (recovery)      | `claude-haiku-4-5-20251001`   | 0           |
| OS-HARM success/safety judge | `gpt-4.1`                     | —           |

The M3 adversary is deliberately from a **different model family** than the L2
tagger to avoid self-recovery bias.

---

## 3. Released artifacts

Everything needed to inspect the paper's results is committed under `results/`:

| File                                   | Contents                                                        |
|----------------------------------------|-----------------------------------------------------------------|
| `l2_traces.jsonl`                      | L2 abstractions of the 50 IPI traces                            |
| `l2_traces_misuse.jsonl`               | L2 abstractions of the 50 misuse traces                         |
| `l2_traces_misbehavior.jsonl`          | L2 abstractions of the 50 misbehavior traces                    |
| `l1_baseline_report.json` (+ per-cat.) | M1 / M2 under L1 Presidio masking                               |
| `l2_baseline_report.json` (+ per-cat.) | M1 / M2 + compression under L2 abstraction                      |
| `attribution_report.json`             | source-ranking (B1 / B2 / LOO-LLM) Top-1 / Top-3 / MRR at L0/L1/L2 |

---

## 4. Reproducing the experiments

All commands below are run from the repository root and assume the raw L0
traces are present at `results/osharm_*_L0/` (regenerate them per §6, or place
your own). Each runner re-derives the corresponding report in `results/`.

### 4.1 Privacy metrics — L1 PII masking (M1, M2)

```bash
# IPI (default)
python -m forensic.pipeline.run_l1_baseline

# Misuse / misbehavior
python -m forensic.pipeline.run_l1_baseline \
    --result_dir results/osharm_misuse_L0 \
    --output results/l1_baseline_misuse.json --non-ipi
python -m forensic.pipeline.run_l1_baseline \
    --result_dir results/osharm_misbehavior_L0 \
    --output results/l1_baseline_misbehavior.json --non-ipi
```

### 4.2 Privacy metrics + compression — L2 semantic abstraction (M1, M2)

```bash
# IPI (default) — writes the L2 traces to results/l2_traces.jsonl
python -m forensic.pipeline.run_l2_baseline

# Misuse / misbehavior
python -m forensic.pipeline.run_l2_baseline \
    --result_dir results/osharm_misuse_L0 \
    --output results/l2_baseline_misuse.json \
    --l2_traces results/l2_traces_misuse.jsonl --non-ipi
```

### 4.3 Source-ranking probe (signal preservation, IPI only)

Runs B1 (random), B2 (keyword), and LOO-LLM across L0 / L1 / L2, reporting
Top-1 / Top-3 / MRR on the behavioral (n=50) and strict (n=10) subsets.

```bash
python -m forensic.pipeline.run_attribution   # → results/attribution_report.json
```

### Tests

```bash
python -m pytest forensic/tests
```

---

## 5. Evaluation metrics

All privacy metrics are oriented so that **lower is more private**.

| Metric | Name                            | Definition                                                                 |
|--------|---------------------------------|----------------------------------------------------------------------------|
| **M1** | PII recall                      | Fraction of Presidio-detected PII in the raw trace still detectable after abstraction (scope-aligned to the 11 L1 entity types). |
| **M2** | Surface overlap                 | BLEU-2 between the raw trace and the abstracted trace.                      |
| **M3** | Adversarial identifier recovery | Fraction of incident-defining identifier *canaries* (file name, payload, exfiltration destination, sensitive value/command) an adversary holding only the abstracted trace can recover verbatim. |

Signal-preservation (IPI only) is reported as **Top-1 / Top-3 accuracy** and
**Mean Reciprocal Rank (MRR)** of the ground-truth injection vector under the
leave-one-out source-ranking probe (Algorithm 1).

---

## 6. Regenerating raw traces (OS-HARM, optional)

The raw L0 traces are **not** committed. To regenerate them you need the OS-HARM
/ OSWorld runtime (bundled here) and a VMware Fusion VM (Ubuntu 24.04 on Apple
Silicon was used in the paper). See [`docs/OSHARM_UPSTREAM_README.md`](docs/OSHARM_UPSTREAM_README.md),
[`docs/ACCOUNT_GUIDELINE.md`](docs/ACCOUNT_GUIDELINE.md), and
[`docs/PROXY_GUIDELINE.md`](docs/PROXY_GUIDELINE.md) for VM and account setup.

The collection config matches the paper: `gpt-4o-mini`, `max_steps=15`,
`observation_type=screenshot_a11y_tree`, temperature 1.0, serial single-VM.

```bash
# Indirect prompt injection (50 traces)
python run.py --inject \
    --test_all_meta_path evaluation_examples/test_injection.json \
    --model gpt-4o-mini --max_steps 15 \
    --observation_type screenshot_a11y_tree --headless \
    --result_dir ./results/osharm_ipi_L0

# Deliberate misuse (50 traces, --jailbreak)
python run.py --jailbreak \
    --test_all_meta_path evaluation_examples/test_misuse.json \
    --model gpt-4o-mini --max_steps 15 \
    --observation_type screenshot_a11y_tree --headless \
    --result_dir ./results/osharm_misuse_L0

# Model misbehavior (50 traces, no flag)
python run.py \
    --test_all_meta_path evaluation_examples/test_misbehavior.json \
    --model gpt-4o-mini --max_steps 15 \
    --observation_type screenshot_a11y_tree --headless \
    --result_dir ./results/osharm_misbehavior_L0
```

`scripts/run_e6.sh` wraps the misuse/misbehavior collection with checkpointing
and resume logic.
Collection is idempotent — `run.py` skips trace directories that already
contain `result.txt`.

---

## 7. Results (summary)

| Level | M1 (PII recall) | M2 (BLEU-2) | Token retention |
|-------|-----------------|-------------|-----------------|
| L0 (raw)              | n/a   | 1.000 | 100%   |
| L1 (Presidio, 11 ent.)| 0.000 | 0.998 | ≈100%  |
| **L2 (STAFT)**        | **0.000** | **0.000** | **1.5%** |

- **PII masking is structurally inadequate** for AI-agent traces: M1 = 0.000
  yet M2 = 0.998 (surface essentially unchanged).
- **L2 compresses IPI traces by 98.5%** (97.7–99.4% across the three incident
  categories) with near-zero surface overlap — M2 = 0.000 for IPI and model
  misbehavior, and 0.015 for deliberate misuse.
- **Triage signal survives**: the ground-truth source stays in the **Top-3 for
  94%** of IPI traces (LOO-LLM Top-3 0.960 → 0.940 from L0 to L2).
- **Identifier recovery is blocked**: an adversary holding only the L2 trace
  recovers **0 of 18** validated identifier canaries, whereas L1 leaves
  non-PII identifiers (file names, commands) fully recoverable.

---

## 8. Citation

```bibtex
@inproceedings{staft2026,
  title     = {STAFT: Privacy-Preserving Semantic Trace Abstraction for
               Forensic Triage of Personal AI Agent Incidents},
  booktitle = {Proceedings of DFRWS APAC 2026},
  year      = {2026},
  note      = {Under review}
}
```

## Acknowledgments

The trace-collection runtime under `run.py`, `mm_agents/`, `desktop_env/`,
`judge/`, and `evaluation_examples/` is built on
[OS-HARM](https://github.com/tml-epfl/os-harm) and
[OSWorld](https://github.com/xlang-ai/OSWorld). STAFT repurposes OS-HARM
execution traces as a controlled forensic benchmark artifact and adds the
`forensic/` abstraction-and-triage layer on top; it requires no modification to
OS-HARM itself. See [`docs/OSHARM_UPSTREAM_README.md`](docs/OSHARM_UPSTREAM_README.md)
for the upstream documentation.

