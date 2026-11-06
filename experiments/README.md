# Experiments

Every script runs from the repository root (`python experiments/<script>.py`) and uses the standard library, plus SciPy and Matplotlib for statistics and figures (`pip install -e ".[analysis]"`). Analyses read committed model outputs, so they need no API access.

The project went through several versions (see `CHANGELOG.md`). Scripts from earlier versions are kept because their outputs are cited in the changelog and the paper's corrections appendix; the current pipeline is marked **current**.

## Current pipeline (paper v0.6)

| Script | What it does |
|---|---|
| `run_grid_v03.py` | **current** Every gate configuration × every decision source (simulated behaviours and real model decisions); writes `results/grid_v03_*.jsonl` |
| `analyze_v03.py` | **current** Heuristic, prose and oracle-structural gate tables; cued model-side conditions; held-out selection; Holm corrections |
| `analyze_r2.py` | **current** Cluster-bootstrap intervals on real traffic, de-cued model side, planners, gate-aware attacks, LLM monitors |
| `analyze_e2e.py` | **current** Structural gate on actions parsed from real Claude messages (four argument policies, three authorization sources) |
| `dynamic_selectors.py` | **current** Dynamic-selector cases: `export`, `parse`, `analyze` (request-only, data, and source-confirmed endorsement) |
| `multihop_v2.py` | **current** Attenuable delegation tokens against nine adversaries |
| `analyze_opencode.py` | **current** Other families as orchestrators, planners, parsers and judges |
| `opencode_gates.py` | **current** Every gate on other families' benign crossings and real attack payloads |
| `export_parse_oc.py`, `analyze_e2e_oc.py` | **current** Parsed structural gate on other families' traffic |
| `make_figures_v04.py` | **current** Figures 1 and 2 of the paper |
| `analyze_multiturn.py` | **current** Scores one-session-per-case runs from `run_multiturn.py` |

## Model runners

| Script | What it does |
|---|---|
| `run_opencode.py` | Batched orchestrator, planner, parser, judge and dynamic-selector tasks on any OpenAI-compatible endpoint (resumable) |
| `run_codex.py` | Orchestrator tasks through the Codex CLI |
| `run_multiturn.py` | One session per case with native function calls; records structured actions |

Claude runs were made with subagents using the wrappers in `data/prompts/`; their raw outputs are under `results/llm*`, `results/realize`, `results/parse*`, `results/judge*`, `results/planner*` and `results/ds`.

## Exporters and ingesters

| Script | What it does |
|---|---|
| `export_data.py` | Scenario catalogue and the first paired model batches |
| `export_v03.py`, `ingest_v03.py` | v0.3 model batches (cued, misconfigured, realistic, realization) and their validation |
| `export_r2.py` | Round-2 de-cued, class-balanced, single-case and large realistic batches |
| `export_parse.py` | Distinct real outgoing messages for the parsers |
| `export_judge_v2.py` | Debiased LLM-monitor items (reference codes stripped, authority clauses, gate-aware items) |
| `ingest_llm.py`, `ingest_realize.py` | Validation of early decision files |

## Earlier versions (kept for the changelog)

| Script | Version | What it did |
|---|---|---|
| `run_grid.py`, `analyze.py`, `deep_analysis.py` | v0.1–v0.2 | First grid and frontier (`results/pooled.json` is still cited for the 94-configuration sweep) |
| `export_judge.py`, `export_judge_adaptive.py`, `export_judge_extra.py`, `analyze_judge.py` | v0.3 | First LLM-judge baseline, superseded by `export_judge_v2.py` |
| `analyze_parse.py` | v0.3 | First parsed-action evaluation, superseded by `analyze_e2e.py` |
| `multihop.py` | v0.3 | Multi-hop experiment that was true by construction, superseded by `multihop_v2.py` |
| `cluster_bootstrap.py`, `robustness_paraphrase.py` | v0.3 | Robustness checks |
| `legacy/make_figures*.py` | v0.1–v0.3 | Superseded figures (written to `paper/figures/legacy/`) |
