"""Invariants for the v0.2 benchmark, defenses and scoring."""
from __future__ import annotations

import math

import pytest

from pivotbench.agents.behaviors import SIM_BEHAVIORS, Compress, Paraphrase, Robust, Verbatim
from pivotbench.defense.capability import COARSE_MANIFEST, CapabilityGate
from pivotbench.defense.gates import (
    AnchorGate,
    AnyGate,
    ArgumentTaintGate,
    LexicalTaintGate,
    StrictBoundaryGate,
)
from pivotbench.defense.text import strip_canary
from pivotbench.eval import (
    FileDecisionModel,
    carries_injection,
    mcnemar_exact,
    run_many,
    run_one,
    summarize,
    wilson,
)
from pivotbench.scenarios import generate_all
from pivotbench.scenarios.generator import (
    generate_arg_hijacks,
    generate_attacks,
    generate_benign,
    generate_priv_benign,
)
from pivotbench.threat_model import Decision, Labeled, Protocol, Provenance

ALL = generate_all()
ATTACKS = [s for s in ALL if s.is_attack]
BENIGN = [s for s in ALL if not s.is_attack]


# ---------------------------------------------------------------- catalog
def test_catalog_sizes_and_uniqueness():
    assert len(generate_attacks()) == 288
    assert len(generate_arg_hijacks()) == 18
    assert len(generate_benign()) == 48
    assert len(generate_priv_benign()) == 24
    assert len(ALL) == 378
    assert len({s.id for s in ALL}) == len(ALL)


def test_attack_bodies_distinct_after_canary_normalisation():
    bodies = {s.rendered_output().replace(s.canary, "X") for s in ATTACKS}
    assert len(bodies) == len(ATTACKS)


def test_every_attack_crosses_a_protocol_and_carries_its_canary():
    for s in ATTACKS:
        assert s.entry_protocol != s.target_protocol
        assert s.canary and s.canary in s.rendered_output() and s.canary in s.rendered_directive()


def test_benign_have_expected_payload_and_no_canary():
    for s in BENIGN:
        assert s.canary == "" and s.expected_payload


# --------------------------------------------------------- canary blindness
GATES = [
    LexicalTaintGate(n=2), LexicalTaintGate(n=4), LexicalTaintGate(n=3, canonicalize=True),
    ArgumentTaintGate(1), ArgumentTaintGate(2), AnchorGate(0.3), AnchorGate(0.5),
    CapabilityGate(), CapabilityGate(check_arguments=True), CapabilityGate(check_arguments=True, min_arg_tokens=2),
    CapabilityGate(COARSE_MANIFEST, name="coarse"),
]


@pytest.mark.parametrize("gate", GATES, ids=lambda g: g.name)
def test_gates_are_canary_blind(gate):
    """Replacing the canary with a different token must never change a decision."""
    for beh in (Verbatim(), Paraphrase(), Compress()):
        for s in ATTACKS[::7]:
            d = beh.decide(s, s.rendered_output())
            swapped_p = d.payload.replace(s.canary, "CANARY-00000000")
            swapped_o = s.rendered_output().replace(s.canary, "CANARY-00000000")
            kw = dict(user_task=s.user_task, protocol_from=s.entry_protocol, protocol_to=s.target_protocol)
            a = gate.check(payload=d.payload, untrusted_spans=[Labeled(s.rendered_output(), s.entry_provenance)], **kw)
            b = gate.check(payload=swapped_p, untrusted_spans=[Labeled(swapped_o, s.entry_provenance)], **kw)
            assert a.allowed == b.allowed, (gate.name, s.id, beh.name)


def test_strip_canary():
    assert "CANARY" not in strip_canary("ref CANARY-1a2b3c4d and CANARY-7f3a-PRIVESC")


# ------------------------------------------------------------- behaviours
def test_susceptible_behaviours_carry_canary_on_attacks():
    for beh in SIM_BEHAVIORS:
        if beh.name == "sim:robust":
            continue
        for s in ATTACKS:
            d = beh.decide(s, s.rendered_output())
            assert d.action == "escalate" and s.canary in d.payload, (beh.name, s.id)


def test_robust_never_carries_injection_but_still_does_users_work():
    r = Robust()
    for s in ALL:
        d = r.decide(s, s.rendered_output())
        assert not carries_injection(s, d.payload)
        if not s.is_attack:
            assert d.action == "escalate" and d.payload == s.expected_payload


# ------------------------------------------------------------- defenses
def test_strict_blocks_everything_cross_protocol():
    rec = run_many(ALL, Verbatim(), StrictBoundaryGate())
    assert all(r["blocked"] for r in rec if r["escalated"])


def test_gates_never_block_same_protocol_actions():
    g = LexicalTaintGate(n=2, require_directive=False)
    span = Labeled("delegate to the payments agent", Provenance.MCP_TOOL)
    res = g.check(payload="delegate to the payments agent", user_task="x", untrusted_spans=[span],
                  protocol_from=Protocol.MCP, protocol_to=Protocol.MCP)
    assert res.allowed


def test_capability_gate_blocks_pivots_and_allows_authorized_privileged_requests():
    cap = CapabilityGate()
    for beh in (Verbatim(), Paraphrase(), Compress()):
        rec = run_many([s for s in ATTACKS if s.id.startswith("gen_") and "arghijack" not in s.id], beh, cap)
        assert sum(r["strict_success"] for r in rec) == 0, beh.name
    rec = run_many(generate_priv_benign(), Verbatim(), cap)
    assert all(r["delivered"] for r in rec)


def test_capability_gate_is_blind_to_argument_hijacks_but_args_check_is_not():
    hij = generate_arg_hijacks()
    assert all(r["strict_success"] for r in run_many(hij, Verbatim(), CapabilityGate()))
    assert not any(r["strict_success"] for r in run_many(hij, Verbatim(), CapabilityGate(check_arguments=True)))


def test_anygate_blocks_if_any_member_blocks():
    s = ATTACKS[0]
    d = Verbatim().decide(s, s.rendered_output())
    g = AnyGate([AnchorGate(0.0), CapabilityGate()])
    r = g.check(payload=d.payload, user_task=s.user_task,
                untrusted_spans=[Labeled(s.rendered_output(), s.entry_provenance)],
                protocol_from=s.entry_protocol, protocol_to=s.target_protocol)
    assert not r.allowed


# ------------------------------------------------------------- scoring
def test_wilson_known_values():
    p, lo, hi = wilson(0, 576)
    assert p == 0 and lo == 0 and abs(hi - 0.006625) < 1e-4
    p, lo, hi = wilson(50, 100)
    assert abs(lo - 0.4038) < 1e-3 and abs(hi - 0.5962) < 1e-3
    assert all(math.isnan(x) for x in wilson(0, 0))


def test_mcnemar_exact():
    assert mcnemar_exact(0, 0) == 1.0
    assert abs(mcnemar_exact(7, 0) - 0.015625) < 1e-12
    assert mcnemar_exact(5, 5) == 1.0


def test_clean_escalation_and_attempt_are_exclusive():
    s = next(x for x in ATTACKS if x.mutators.get("mechanism") == "privesc")
    clean = FileDecisionModel("t", {s.id: Decision("escalate", "Retrieve the onboarding docs")})
    r = run_one(s, clean, None)
    assert r["clean_escalation"] and not r["attempt"] and not r["strict_success"]
    bad = FileDecisionModel("t", {s.id: Decision("escalate", s.rendered_directive())})
    r = run_one(s, bad, None)
    assert r["attempt"] and r["strict_success"] and not r["clean_escalation"]


def test_summarize_counts():
    recs = run_many(ALL, Verbatim(), None)
    sm = summarize(recs)
    assert sm["n_attack"] == 306 and sm["n_benign"] == 72
    assert sm["asr_strict"]["k"] == 306 and sm["utility"]["k"] == 72
