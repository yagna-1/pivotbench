"""PivotBench command-line interface.

Examples:
  pivotbench list                                  # v0.1 hand-written scenarios
  pivotbench list --suite full                     # all 378 generated scenarios (summary)
  pivotbench run                                   # v0.1 suite, vulnerable model, v0.1 gate
  pivotbench run --suite full --behavior paraphrase --gate lexical
  pivotbench run --suite full --behavior paraphrase --gate capability+args
  pivotbench run --suite full --model openai --model-name gpt-4o --gate capability+args \
                 --json out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from . import __version__
from .agents.behaviors import Compress, Mixer, Paraphrase, Robust, Verbatim
from .agents.model_adapter import build_model
from .defense.capability import CapabilityGate
from .defense.gates import AnchorGate, ArgumentTaintGate, LexicalTaintGate, StrictBoundaryGate
from .defense.taint import TaintGate
from .eval import run_many, summarize
from .harness import run_suite
from .report import print_report, to_json, to_markdown
from .scenarios import SCENARIOS, generate_all, get_scenario

BEHAVIORS = {"verbatim": Verbatim, "paraphrase": Paraphrase, "compress": Compress,
             "mixer": Mixer, "robust": Robust}
GATES = {
    "none": lambda: None,
    "v0.1": TaintGate,
    "lexical": lambda: LexicalTaintGate(n=3, canonicalize=True),
    "argument": ArgumentTaintGate,
    "anchor": lambda: AnchorGate(0.3),
    "strict": StrictBoundaryGate,
    "capability": CapabilityGate,
    "capability+args": lambda: CapabilityGate(check_arguments=True, min_arg_tokens=2),
}


def _cmd_list(args: argparse.Namespace) -> int:
    if args.suite == "v0.1":
        for s in SCENARIOS:
            print(f"{s.id:24s} {s.entry_protocol.value}→{s.target_protocol.value:4s}  {s.title}")
        return 0
    allsc = generate_all()
    c = Counter((s.label, s.mutators.get("mechanism", s.mutators.get("base", "?")).split(":")[0]) for s in allsc)
    for (label, key), n in sorted(c.items()):
        print(f"{label:7s} {key:18s} {n:4d}")
    print(f"total {len(allsc)}")
    return 0


def _pct(w: dict) -> str:
    return f"{w['p']*100:5.1f}% [{w['lo']*100:.1f}, {w['hi']*100:.1f}]  ({w['k']}/{w['n']})"


def _cmd_run(args: argparse.Namespace) -> int:
    gate = GATES[args.gate]()
    if args.model == "sim":
        model = BEHAVIORS[args.behavior]()
    else:
        try:
            model = build_model(kind=args.model, model_name=args.model_name,
                                base_url=args.base_url, api_key_env=args.api_key_env)
        except (ValueError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.suite == "v0.1":
        scenarios = SCENARIOS if not args.scenario else [get_scenario(i) for i in args.scenario]
        suite = run_suite(scenarios, model, gate)
        print_report(suite)
        if args.json:
            open(args.json, "w").write(to_json(suite))
        if args.md:
            open(args.md, "w").write(to_markdown(suite) + "\n")
        return 0

    scenarios = generate_all()
    if args.scenario:
        keep = set(args.scenario)
        scenarios = [s for s in scenarios if s.id in keep]
    recs = run_many(scenarios, model, gate)
    sm = summarize(recs)
    print(f"PivotBench v{__version__} — model={getattr(model, 'name', '?')} gate={args.gate}")
    print(f"  attack scenarios   {sm['n_attack']}   benign scenarios {sm['n_benign']}")
    print(f"  strict ASR         {_pct(sm['asr_strict'])}")
    print(f"  model attempt rate {_pct(sm['model_attempt_rate'])}")
    print(f"  gate catch rate    {_pct(sm['gate_catch_rate'])}")
    print(f"  benign utility     {_pct(sm['utility'])}")
    print(f"  gate FPR           {_pct(sm['gate_fpr'])}")
    print(f"  gate latency       mean {sm['gate_ms_mean']:.4f} ms, p99 {sm['gate_ms_p99']:.4f} ms")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"summary": sm, "records": recs}, fh, indent=1, default=str)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pivotbench", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"pivotbench {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", help="list scenarios")
    ls.add_argument("--suite", choices=["v0.1", "full"], default="v0.1")
    ls.set_defaults(func=_cmd_list)

    r = sub.add_parser("run", help="run the benchmark")
    r.add_argument("--suite", choices=["v0.1", "full"], default="v0.1")
    r.add_argument("--model", default="vulnerable", choices=["vulnerable", "robust", "sim", "openai"],
                   help="orchestrator: deterministic v0.1 stand-ins, a simulated behaviour, or a real model")
    r.add_argument("--behavior", choices=sorted(BEHAVIORS), default="verbatim",
                   help="simulated orchestrator behaviour (with --model sim)")
    r.add_argument("--gate", choices=sorted(GATES), default="v0.1")
    r.add_argument("--no-defense", dest="gate", action="store_const", const="none",
                   help="alias for --gate none")
    r.add_argument("--defense", dest="gate", action="store_const", const="v0.1",
                   help="alias for --gate v0.1 (backward compatible)")
    r.add_argument("--model-name", help="model id for --model openai")
    r.add_argument("--base-url", help="OpenAI-compatible base URL")
    r.add_argument("--api-key-env", default="OPENAI_API_KEY")
    r.add_argument("--scenario", action="append", help="run only this scenario id (repeatable)")
    r.add_argument("--json", help="write JSON results here")
    r.add_argument("--md", help="write Markdown results here (v0.1 suite)")
    r.set_defaults(func=_cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run" and args.suite == "full" and args.model in ("vulnerable", "robust"):
        args.model, args.behavior = "sim", ("verbatim" if args.model == "vulnerable" else "robust")
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
