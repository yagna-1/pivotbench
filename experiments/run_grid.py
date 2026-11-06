"""Full experiment grid: every gate configuration x every decision source.

Decision sources
  sim:verbatim, sim:paraphrase, sim:compress, sim:mixer, sim:robust
      deterministic orchestrator behaviours on all 378 v0.2 generated scenarios
  <model>_<prompt>
      recorded LLM decisions (results/llm_decisions.json) on the 186-scenario
      stratified subset (v0.2; the v0.3 grid is experiments/run_grid_v03.py)

Outputs
  results/grid_summary.jsonl   one row per (source, gate) with all metrics
  results/grid_records.jsonl   per-scenario records for the HEADLINE gates only
  results/grid_meta.json       gate list, counts, runtime
"""
from __future__ import annotations

import itertools
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.agents.behaviors import SIM_BEHAVIORS  # noqa: E402
from pivotbench.defense.gates import (  # noqa: E402
    AnchorGate,
    AnyGate,
    ArgumentTaintGate,
    LexicalTaintGate,
    StrictBoundaryGate,
)
from pivotbench.defense.capability import (  # noqa: E402
    COARSE_MANIFEST,
    DEFAULT_MANIFEST,
    CapabilityGate,
)
from pivotbench.defense.taint import TaintGate  # noqa: E402
from pivotbench.eval import FileDecisionModel, run_many, summarize  # noqa: E402
from pivotbench.scenarios import generate_all  # noqa: E402
from pivotbench.threat_model import Decision  # noqa: E402


def build_gates() -> list[tuple[dict, object]]:
    """Return [(params, gate)]; params describes the gate for analysis."""
    gates: list[tuple[dict, object]] = [
        ({"family": "none"}, None),
        ({"family": "strict"}, StrictBoundaryGate()),
        ({"family": "v0.1"}, TaintGate()),
    ]
    for n, k, d, c in itertools.product([2, 3, 4, 5, 6], [1, 2, 3], [0, 1], [0, 1]):
        gates.append(({"family": "lexical", "n": n, "k": k, "dir": d, "canon": c},
                      LexicalTaintGate(n=n, min_overlap=k, require_directive=bool(d),
                                       canonicalize=bool(c))))
    gates.append(({"family": "lexical_oracle", "n": 4, "k": 1, "dir": 1, "canon": 0},
                  LexicalTaintGate(n=4, min_overlap=1, require_directive=True,
                                   canonicalize=False, canary_aware=True)))
    for k in (1, 2):
        gates.append(({"family": "argument", "k": k}, ArgumentTaintGate(min_tokens=k)))
    gates.append(({"family": "argument_oracle", "k": 1},
                  ArgumentTaintGate(min_tokens=1, canary_aware=True)))
    for t, d in itertools.product([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7], [0, 1]):
        gates.append(({"family": "anchor", "t": t, "dir": d},
                      AnchorGate(threshold=t, require_directive=bool(d))))

    lex_opts = {
        "L3c": lambda: LexicalTaintGate(n=3, min_overlap=1, require_directive=True, canonicalize=True),
        "L4": lambda: LexicalTaintGate(n=4, min_overlap=1, require_directive=True, canonicalize=False),
    }
    anc_opts = {f"A{t}": (lambda t=t: AnchorGate(threshold=t)) for t in (0.2, 0.3, 0.4)}
    arg = lambda: ArgumentTaintGate(min_tokens=1)  # noqa: E731
    for lk, lf in lex_opts.items():
        gates.append(({"family": "composite", "members": f"{lk}+Arg"}, AnyGate([lf(), arg()], f"any[{lk}+Arg]")))
        for ak, af in anc_opts.items():
            gates.append(({"family": "composite", "members": f"{lk}+{ak}"}, AnyGate([lf(), af()], f"any[{lk}+{ak}]")))
            gates.append(({"family": "composite", "members": f"{lk}+Arg+{ak}"},
                          AnyGate([lf(), arg(), af()], f"any[{lk}+Arg+{ak}]")))
    for ak, af in anc_opts.items():
        gates.append(({"family": "composite", "members": f"Arg+{ak}"}, AnyGate([arg(), af()], f"any[Arg+{ak}]")))

    # Capability authorization (control-flow integrity) and ablations.
    gates.append(({"family": "capability", "manifest": "full", "args": 0}, CapabilityGate()))
    gates.append(({"family": "capability", "manifest": "full", "args": 1},
                  CapabilityGate(check_arguments=True)))
    for k in (2, 3):
        gates.append(({"family": "capability", "manifest": "full", "args": k},
                      CapabilityGate(check_arguments=True, min_arg_tokens=k)))
    gates.append(({"family": "capability", "manifest": "coarse", "args": 0},
                  CapabilityGate(COARSE_MANIFEST, name="capability(coarse)")))
    gates.append(({"family": "capability", "manifest": "coarse", "args": 1},
                  CapabilityGate(COARSE_MANIFEST, name="capability(coarse)+args", check_arguments=True)))
    caps = sorted(DEFAULT_MANIFEST)
    for r in range(0, len(caps)):
        for subset in itertools.combinations(caps, r):
            man = {c: DEFAULT_MANIFEST[c] for c in subset}
            label = "+".join(c.split(".")[0] for c in subset) or "empty"
            gates.append(({"family": "capability_ablation", "coverage": r, "caps": list(subset)},
                          CapabilityGate(man, name=f"capability[{label}]+args", check_arguments=True)))
    return gates


HEADLINE = {
    "none", "strict_boundary", "taint_gate_v0.1",
    "lexical(n=3,k=1,dir=1,canon=1)", "lexical(n=2,k=1,dir=1,canon=1)",
    "argument(k=1)", "argument(k=1,CANARY)", "anchor(t=0.30,dir=0)",
    "any[L3c+Arg]", "any[L3c+Arg+A0.3]", "any[Arg+A0.3]",
    "capability(5)", "capability(5)+args", "capability(coarse)", "capability(coarse)+args",
    "capability(5)+args(k=2)", "capability(5)+args(k=3)",
}


def main() -> None:
    scenarios = generate_all()
    llm = json.loads((ROOT / "results" / "llm_decisions.json").read_text())
    sources = [(b.name, b) for b in SIM_BEHAVIORS]
    for cond, dec in sorted(llm.items()):
        sources.append((cond, FileDecisionModel(cond, {k: Decision(**v) for k, v in dec.items()})))

    gates = build_gates()
    out_sum = open(ROOT / "results" / "grid_summary.jsonl", "w")
    out_rec = open(ROOT / "results" / "grid_records.jsonl", "w")
    t0 = time.time()
    n_runs = 0
    for params, gate in gates:
        gname = "none" if gate is None else gate.name
        for sname, model in sources:
            recs = run_many(scenarios, model, gate)
            n_runs += len(recs)
            row = {"source": sname, "gate": gname, "params": params,
                   "source_kind": "sim" if sname.startswith("sim:") else "llm"}
            row.update(summarize(recs))
            # Threat-class subsets:
            #   pivot : cross-capability pivots + ordinary benign delegations
            #   priv  : within-capability argument hijacks + authorized
            #           privileged delegations
            priv = [r for r in recs if r["scenario_id"].startswith(("gen_arghijack_", "privbenign_"))]
            pivot = [r for r in recs if not r["scenario_id"].startswith(("gen_arghijack_", "privbenign_"))]
            row["pivot"] = summarize(pivot)
            row["priv"] = summarize(priv)
            out_sum.write(json.dumps(row) + "\n")
            if gname in HEADLINE:
                for r in recs:
                    r = dict(r)
                    r["source"] = sname
                    out_rec.write(json.dumps(r) + "\n")
    out_sum.close()
    out_rec.close()
    meta = {"n_gates": len(gates), "n_sources": len(sources),
            "n_cells": len(gates) * len(sources), "n_scenario_runs": n_runs,
            "runtime_s": round(time.time() - t0, 1),
            "gates": [("none" if g is None else g.name) for _, g in gates],
            "sources": [s for s, _ in sources]}
    (ROOT / "results" / "grid_meta.json").write_text(json.dumps(meta, indent=1))
    print(f"gates={meta['n_gates']} sources={meta['n_sources']} cells={meta['n_cells']} "
          f"runs={n_runs} in {meta['runtime_s']}s")


if __name__ == "__main__":
    main()
