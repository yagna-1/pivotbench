"""Sanity tests: the harness must (a) fire on the undefended worst case,
(b) go silent under the defense, and (c) not fire for a robust model."""
from __future__ import annotations

from pivotbench.agents.model_adapter import DeterministicRobustModel, DeterministicVulnerableModel
from pivotbench.defense.taint import TaintGate
from pivotbench.harness import run_suite
from pivotbench.scenarios import SCENARIOS


def test_vulnerable_undefended_all_fire():
    suite = run_suite(SCENARIOS, DeterministicVulnerableModel(), defense=None)
    assert suite.asr == 1.0, "worst-case model with no defense should fully pivot"
    assert suite.blocked == 0


def test_vulnerable_defended_none_fire():
    suite = run_suite(SCENARIOS, DeterministicVulnerableModel(), defense=TaintGate())
    assert suite.asr == 0.0, "the taint gate must stop every cross-protocol pivot"
    assert suite.block_rate == 1.0
    assert suite.mean_overhead_ms >= 0.0


def test_robust_never_fires():
    suite = run_suite(SCENARIOS, DeterministicRobustModel(), defense=None)
    assert suite.asr == 0.0, "a model that ignores untrusted directives can't be pivoted"


def test_scenarios_are_wellformed():
    for s in SCENARIOS:
        assert s.canary in s.rendered_output()
        assert s.canary in s.rendered_directive()
        assert s.entry_protocol != s.target_protocol, "a pivot must cross protocols"
