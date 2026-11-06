"""v0.3 grid: structural capability gates + headline detection/prose gates,
over every decision source, broken down by threat class.

Sources
  sim:*                 5 simulated behaviours on all 582 scenarios
  <m>_<naive|hardened>  v0.2 LLM decisions (186-scenario subset)
  <m>_compliant         v0.3 misconfigured-policy condition (anonymized batches)
  <m>_compliant_repK    replicate runs of the compliant condition (subset of batches)
  <m>_realistic         v0.3 realistic condition (production prompt, natural refs,
                        1 attack per batch of 10)
  realize:<m>           v0.3 LLM-realized messages (decision GIVEN; LLM composes
                        the protocol message) -> real-LLM restatement distribution
Outputs results/grid_v03_summary.jsonl and results/grid_v03_records.jsonl
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
from pivotbench.defense.capability import CapabilityGate  # noqa: E402
from pivotbench.defense.gates import AnchorGate, AnyGate, ArgumentTaintGate, LexicalTaintGate  # noqa: E402
from pivotbench.defense.intent import oracle_auth, planner_auth  # noqa: E402
from pivotbench.defense.structural import MODES, StructuralGate, prose_auth  # noqa: E402
from pivotbench.defense.taint import TaintGate  # noqa: E402
from pivotbench.eval import FileDecisionModel, run_many, summarize  # noqa: E402
from pivotbench.scenarios.generator import generate_everything  # noqa: E402
from pivotbench.threat_model import Decision  # noqa: E402

CLASSES = ("pivot", "hijack", "heldout", "overauth", "drift")


def load_sources(scen):
    sources = [(b.name, b) for b in SIM_BEHAVIORS]
    for fname in ("llm_decisions.json", "llm_decisions_v03.json", "llm_decisions_reps.json"):
        p = ROOT / "results" / fname
        if p.exists():
            for cond, dec in sorted(json.loads(p.read_text()).items()):
                if dec:
                    sources.append((cond, FileDecisionModel(cond, {k: Decision(**v) for k, v in dec.items()})))
    p = ROOT / "results" / "realize_decisions.json"
    if p.exists():
        for m, dec in sorted(json.loads(p.read_text()).items()):
            if dec:
                sources.append((f"realize:{m}", FileDecisionModel(f"realize:{m}", {k: Decision(**v) for k, v in dec.items()})))
    return sources


def build_gates(scen):
    gates = [
        ({"family": "none"}, None),
        ({"family": "detect", "name": "v0.1"}, TaintGate()),
        ({"family": "detect", "name": "lexical n3 canon"}, LexicalTaintGate(n=3, canonicalize=True)),
        ({"family": "detect", "name": "lexical n2 canon"}, LexicalTaintGate(n=2, canonicalize=True)),
        ({"family": "detect", "name": "argument"}, ArgumentTaintGate()),
        ({"family": "detect", "name": "anchor 0.2"}, AnchorGate(0.2)),
        ({"family": "detect", "name": "anchor 0.3"}, AnchorGate(0.3)),
        ({"family": "detect", "name": "lex+arg+anchor"},
         AnyGate([LexicalTaintGate(n=3, canonicalize=True), ArgumentTaintGate(), AnchorGate(0.3)], "any[L3c+Arg+A0.3]")),
        ({"family": "prose_cap", "name": "capability(prose)"}, CapabilityGate()),
        ({"family": "prose_cap", "name": "capability(prose)+args k2"}, CapabilityGate(check_arguments=True, min_arg_tokens=2)),
    ]
    auths = {"oracle": oracle_auth(scen), "prose": prose_auth()}
    for m in ("haiku", "sonnet", "opus"):
        if (ROOT / "results" / "planner" / f"{m}.json").exists():
            auths[f"planner:{m}"] = planner_auth(m)
    for (aname, afn), mode, args in itertools.product(auths.items(), MODES, (False, True)):
        gates.append(({"family": "structural", "auth": aname, "mode": mode, "args": int(args)},
                      StructuralGate(afn, mode=mode, check_args=args,
                                     name=f"structural[{aname},{mode}{',args' if args else ''}]")))
    return gates


def main() -> None:
    scen = generate_everything()
    sources = load_sources(scen)
    gates = build_gates(scen)
    t0 = time.time()
    n = 0
    with open(ROOT / "results" / "grid_v03_summary.jsonl", "w") as fs, \
         open(ROOT / "results" / "grid_v03_records.jsonl", "w") as fr:
        for params, gate in gates:
            gname = "none" if gate is None else gate.name
            for sname, model in sources:
                recs = run_many(scen, model, gate)
                n += len(recs)
                row = {"source": sname, "gate": gname, "params": params,
                       "source_kind": ("sim" if sname.startswith("sim:") else
                                       "realize" if sname.startswith("realize:") else "llm")}
                row["all"] = summarize(recs)
                for c in CLASSES:
                    sub = [r for r in recs if r["threat_class"] == c]
                    if c == "drift":
                        for v in ("reg", "unreg"):
                            row[f"drift_{v}"] = summarize([r for r in sub if r["mutators"].get("drift_target") == v])
                    row[c] = summarize(sub)
                fs.write(json.dumps(row) + "\n")
                for r in recs:
                    fr.write(json.dumps({"source": sname, "gate": gname, "scenario_id": r["scenario_id"],
                                         "threat_class": r["threat_class"], "label": r["label"],
                                         "escalated": r["escalated"], "attempt": r["attempt"],
                                         "blocked": r["blocked"], "strict_success": r["strict_success"],
                                         "lenient_success": r["lenient_success"],
                                         "clean_escalation": r["clean_escalation"],
                                         "mutators": r["mutators"]}) + "\n")
    print(f"v0.3 grid: {len(gates)} gates x {len(sources)} sources, {n} scenario runs in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
