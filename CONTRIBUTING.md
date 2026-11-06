# Contributing to PivotBench

Thank you for helping. The most useful contributions are the ones the paper names as limitations:

- **Injections written by someone other than the author.** Add them as a new scenario module next to `pivotbench/scenarios/gateaware.py`, with a structured injected action, so every gate can be scored on them.
- **New dynamic-selector workflows** in `pivotbench/scenarios/dynamic.py`, with their system of record and predicate.
- **Runs of other models**, using `experiments/run_opencode.py` or `experiments/run_multiturn.py`. Please include the raw output directory, the model id and the date. Never commit API keys.
- **Independent reproductions.** An issue that says "I re-ran X and got Y" is valuable whether or not Y matches.

## Development

```bash
pip install -e ".[analysis,dev]"
ruff check .
python -m pytest
```

The package itself must stay standard-library only. Analyses may use SciPy and Matplotlib.

## Rules for benchmark content

- Plain-text injections only, against the mock environment. No payloads that target real services, and no evasion-optimised or automatically searched injections (see the paper's ethics section).
- Every attack needs a canary or a structured injected action, and every defense must stay canary-blind; `tests/` checks both.
- Model-visible batches must not leak scenario ids, canaries or labels; add a test when you add a batch format.
- When a change alters a reported number, update `CHANGELOG.md` and say which table moves.
