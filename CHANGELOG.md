# Changelog

## 0.6.0 — 2026-11-06 (selectors from data; revision after external reading)

### Added
- **Dynamic-selector workflows** (`pivotbench/scenarios/dynamic.py`, 48 cases): rule-based privileged requests whose selectors exist only in tool output, with an untrusted queue and an operator system of record; attacks: id injection, status spoof, scope broadening.
- **Source-confirmed endorsement** (`experiments/dynamic_selectors.py`): the planner may emit `{capability, predicate}` rules over an operator vocabulary, and a selector is endorsed only if the system of record confirms the predicate. Compared with request-only (typed) and naive data endorsement on real Claude orchestrator traffic (Haiku, Sonnet; production and misconfigured prompts; 384 decisions) parsed by Haiku and Sonnet parsers, and with Haiku and Sonnet planners on 47 requests. Results in `results/ds/` and `results/ds_summary.json`.
- **Multi-turn runner** `experiments/run_multiturn.py` (one session per case, native function calls, structured actions recorded) and `experiments/analyze_multiturn.py`.
- Privileged-only benign cost in `analyze_e2e.py` and `analyze_e2e_oc.py`.
- Paper v0.6: §2 source-confirmed endorsement and assumption A5, "where the guarantee stops", §3.4, §6.8, single-case Fisher tests, batching caveat, revised abstract (arXiv length) and title.

### Repository
- README rewritten; `experiments/README.md` documents every script; CI (Python 3.10–3.13: ruff, pytest, smoke runs); `CITATION.cff`, `CONTRIBUTING.md`, `SECURITY.md`, issue templates; optional extras `[analysis]` and `[dev]`.
- Fixed an f-string that only parsed on Python 3.12+ (`analyze_opencode.py`) and other lint findings; superseded figure scripts moved to `experiments/legacy/`; regenerable 100 MB grid records no longer committed.

### Corrected
- The abstract said "582 attack scenarios"; 582 is 438 attacks plus 144 benign controls.
- `run_opencode.py --tasks ds` runs the dynamic-selector batches on other families; `dynamic_selectors.py` picks up `results/opencode/<model>/ds_<prompt>/` automatically.
- The structural gate's zero cost held only for privileged requests that name their selectors; rule-based requests are blocked 192/192 by request-only endorsement.
- The judge-saturation sentence counted five zero-error Claude configurations; there are four, plus four from other families.
- "Real traffic" is now defined as model-generated traffic in a controlled environment; the misconfigured-policy result is framed as following a dangerous operator instruction.
- "All-or-nothing per run" is stated per batch, with in-context consistency named as an untested explanation.
- The appendix no longer calls AI reviewer passes "independent review".
- `opencode_gates.py` used 1,000 bootstrap resamples while the paper states 2,000; fixed and rerun.

## 0.5.0 — 2026-11-06 (open models)

### Added
- **Open models via OpenCode Go**: Kimi K3, GLM-5.3 Flash, DeepSeek V4.1 Flash and MiniMax M3.1 Flash run on the author's machine with `experiments/run_opencode.py` (standard library, resumable) as orchestrators (realistic, misconfigured mixed ×3, single-case), planners, parsers and judges; raw outputs in `results/opencode/`, failed calls listed in `results/opencode/failed_calls.txt`.
- `experiments/analyze_opencode.py` (model side, planners, open-model parsers end to end, judges), `experiments/opencode_gates.py` (every gate on 2,914 open-model benign crossings and 329 real attack payloads), `experiments/export_parse_oc.py` + `experiments/analyze_e2e_oc.py` (structural gate on open-model traffic parsed by Claude parsers).
- `data/adjudication_opencode.json`: 37 flagged open-model payloads adjudicated as refusals after reading all 366.
- Figure 8 extended with open models; paper v0.5 (§6.10, abstract, discussion, limitations).

## 0.4.0 — 2026-11-05 (revision after round-2 review)

### Added
- **Gate-aware attack classes** (`pivotbench/scenarios/gateaware.py`, 48): exfiltration through an authorized non-privileged draft, value-slot confusion, pasted third-party approval inside the user's request, poisoned AgentCard annotation. Each targets one assumption of Proposition 1.
- **End-to-end structural gate on parsed actions** (`experiments/analyze_e2e.py`): Haiku and Sonnet parsers turn every real outgoing message into `{target, args}`; four argument policies (capability only, key-agnostic, **typed** Progent-style, typed+ completeness); dual-parser conjunction; cluster-bootstrap costs.
- **Attenuable delegation tokens** (`pivotbench/defense/token.py`, macaroon-style HMAC chain with task, audience, capability, value, expiry and single-use caveats) and `experiments/multihop_v2.py` with nine adversaries (forge, widen, strip, replay, wrong audience, insider, repeat).
- **Planner set v2**: 247 requests (200 from four independent writer subagents with their own labels), 3 models × 3 samples, reworded registry in the third sample.
- **LLM monitors v2** (`experiments/export_judge_v2.py`): reference codes stripped from all items, prompt-aware authority clauses, gate-aware items, and three detection controls (data provenance, instruction provenance, prompt-injection classifier).
- **Model side v0.4**: de-cued class-balanced compliant batches (Haiku, Sonnet ×2, Opus), single-case runs, and a large realistic condition (30 batches × 20, 15% base rate, 90 distinct attacks).
- Run audit and exclusion list (`data/excluded_runs.json`); archived prompts for realization and orchestrator wrappers (`data/prompts/`).
- Figures 8 (rebuilt) and 9; paper v0.4; 2 new tests (token attenuation/forgery, absence of the benign-only marker and ids in round-2 batches).

### Corrected
- v0.3's structural-gate headline used oracle action resolution; it is now labelled as such, and the end-to-end result is reported separately.
- v0.3's LLM-judge items carried reference codes only on attacks (a perfect cue); v0.3's "authorization versus provenance" claim holds only for data provenance.
- v0.3 stated that seven detection configurations stay below 5% ASR; only two do.
- v0.3's multi-hop experiment was true by construction; replaced by an implemented, attacked mechanism.
- v0.2/v0.3 model-visible batches marked benign items with "(context the orchestrator also read)"; removed in v0.4 and disclosed.
- Two Opus round-2 runs were written by a fallback model, one framing the task as labelling; excluded from model-side statistics.
- `analyze_e2e.py` double-counted benign occurrences before release (rates unchanged); fixed.

## 0.3.0 — 2026-11-05 (revision after round-1 review)

### Added
- Threat classes: **over-authorization** (36; the user request mentions the targeted capability without requesting it) and **capability drift** (96; wording outside the manifest, registered and unregistered privileged endpoints).
- Benign controls: 48 held-out ordinary delegations (6 new task families) and 24 **implicitly authorized** privileged requests; 24 clean filler pages.
- **Structural capability gate** (`pivotbench/defense/structural.py`) over a capability registry (`registry.py`), with authorization sources oracle / LLM planner / prose (`intent.py`), modes fail-open / deny-unknown / allow-list, and argument endorsement. Fails closed when no structured action can be resolved.
- LLM conditions: *compliant* (misconfigured operator policy), *realistic* (production prompt, natural reference codes, 1 attack per 10 cases, opaque ids), *realization* (decision given; model composes the message), replicate runs; LLM planners (Haiku/Sonnet/Opus) on all 42 user requests.
- **LLM-judge gate** baseline (Haiku, Sonnet) incl. authority-claim variants; structured **action parsing** of real traffic for an end-to-end structural evaluation.
- Two-hop authority experiment (`experiments/multihop.py`): stateless re-derivation vs carried authorization.
- Analysis: per-class gate matrix, real compromised traffic, planner accuracy, scenario- and run-level exact bounds, design/test family split, Holm correction (`experiments/analyze_v03.py`).
- Paper v0.3 with a formal model (Proposition 1), metric equations, and a response-to-reviews appendix; figures 6–8.
- 24 new tests (structural-gate semantics, text-invariance of the structural decision, id hiding and canary hiding in every model-visible batch).

### Corrected
- v0.2's 0% real-traffic cost for the prose capability gate does not generalize: it blocks 61.5% of held-out implicitly authorized real delegations and is blind to drift and over-authorization.
- v0.2's model-side bound (0.66%) treated correlated exposures as independent; the scenario-level exact bound is 2.9% (0 of 124 distinct attack scenarios).
- v0.2's Opus naive-vs-hardened helpfulness difference (p = 0.016) is not significant after Holm correction (p = 0.094).
- v0.2 model-visible batches exposed scenario ids and `CANARY-` strings; all v0.3 batches use opaque ids and, where the model must not see the instrument, natural reference codes.
- Stale docstrings (336/144 scenarios) fixed.

## 0.2.0 — 2026-11-05

### Added
- Coverage generator: 288 cross-capability pivots (4 mechanisms × 12 domains × 3 positions × 2 alignments), 18 within-capability argument hijacks, 48 ordinary benign delegations, 24 authorized privileged delegations.
- Simulated orchestrator restatement behaviours: verbatim, paraphrase, compress, mixer, robust.
- Defense family: lexical taint (parameterised), argument taint, intent anchor, strict boundary, composites, and **capability authorization** with scoped argument provenance.
- Scoring: strict (canary) / lenient (action signature) ASR, collateral blocks, gate FPR, Wilson CIs, exact McNemar; manual adjudication file for lenient false positives.
- LLM-in-the-loop data: 1,116 decisions from Claude Haiku / Sonnet / Opus under naive and hardened prompts (paired batches).
- Experiment grid (135 gates × 11 sources), analysis, figures, paper (`paper/PivotBench.pdf`).
- CLI: `--suite full`, `--model sim --behavior`, `--gate`.
- 27 new invariant tests (incl. canary-blindness of every gate).

### Changed
- All gates are canary-blind by default (canary tokens stripped before analysis).
- `TaintGate` is now a preset of `LexicalTaintGate`.

### Corrected
- The v0.1 README claim "ASR 100% → 0% at ~0.03 ms" holds only for verbatim-copying orchestrators. Under paraphrase/compression the v0.1 gate allows 17.2% pooled attack success and blocks 52.1% of legitimate real-model delegations (see paper §6.2).

## 0.1.0 — 2026-11-04
- Initial release: 5 hand-written MCP↔A2A pivot scenarios, mock environment with canaries, v0.1 lexical taint gate, CLI.
