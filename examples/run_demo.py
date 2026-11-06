"""Reproduce the headline numbers with no API key:

    python examples/run_demo.py

Runs the worst-case susceptible model undefended, then defended, and prints the
ASR delta the taint gate buys.
"""
from __future__ import annotations

from pivotbench.agents.model_adapter import DeterministicVulnerableModel
from pivotbench.defense.taint import TaintGate
from pivotbench.harness import run_suite
from pivotbench.report import print_report
from pivotbench.scenarios import SCENARIOS


def main() -> None:
    model = DeterministicVulnerableModel()

    print("=" * 64)
    print("BASELINE — susceptible orchestrator, no cross-protocol defense")
    print("=" * 64)
    base = run_suite(SCENARIOS, model, defense=None)
    print_report(base)

    print("\n" + "=" * 64)
    print("DEFENDED — same orchestrator behind the taint gate")
    print("=" * 64)
    defended = run_suite(SCENARIOS, model, defense=TaintGate())
    print_report(defended)

    print(f"\nASR: {base.asr:.0%} → {defended.asr:.0%}  "
          f"(gate overhead ~{defended.mean_overhead_ms:.3f} ms/decision)")


if __name__ == "__main__":
    main()
