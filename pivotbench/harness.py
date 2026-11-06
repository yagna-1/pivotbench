"""The benchmark harness: run scenarios against an orchestrator and score them."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .agents.model_adapter import Model
from .agents.orchestrator import Orchestrator
from .defense.taint import TaintGate
from .env import CanarySink, SensitiveAction
from .scenarios.base import Scenario
from .threat_model import AuditEvent


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    protocol_from: str
    protocol_to: str
    attack_fired: bool          # canary tripped -> attack succeeded
    blocked_by_defense: bool    # the gate stopped it
    defense_overhead_ms: float
    events: list[AuditEvent] = field(default_factory=list)


@dataclass
class SuiteResult:
    model: str
    defense_on: bool
    results: list[ScenarioResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def attacks_fired(self) -> int:
        return sum(r.attack_fired for r in self.results)

    @property
    def asr(self) -> float:
        """Attack Success Rate."""
        return self.attacks_fired / self.total if self.total else 0.0

    @property
    def blocked(self) -> int:
        return sum(r.blocked_by_defense for r in self.results)

    @property
    def block_rate(self) -> float:
        return self.blocked / self.total if self.total else 0.0

    @property
    def mean_overhead_ms(self) -> float:
        vals = [r.defense_overhead_ms for r in self.results if r.defense_overhead_ms > 0]
        return sum(vals) / len(vals) if vals else 0.0


def run_scenario(scenario: Scenario, model: Model, defense: Optional[TaintGate]) -> ScenarioResult:
    sink = CanarySink()
    action = SensitiveAction(
        sink=sink,
        name=f"{scenario.target_protocol.value}-sensitive-action",
        target_protocol=scenario.target_protocol,
    )
    orch = Orchestrator(model=model, defense=defense)
    events = orch.run(scenario, action)

    blocked = any(e.kind == "blocked" for e in events)
    overhead = next(
        (e.data["latency_ms"] for e in events if e.kind in ("blocked", "allowed")
         and "latency_ms" in e.data),
        0.0,
    )

    return ScenarioResult(
        scenario_id=scenario.id,
        title=scenario.title,
        protocol_from=scenario.entry_protocol.value,
        protocol_to=scenario.target_protocol.value,
        attack_fired=sink.was_tripped(scenario.canary),
        blocked_by_defense=blocked,
        defense_overhead_ms=overhead,
        events=events,
    )


def run_suite(
    scenarios: list[Scenario],
    model: Model,
    defense: Optional[TaintGate],
) -> SuiteResult:
    results = [run_scenario(s, model, defense) for s in scenarios]
    return SuiteResult(
        model=model.name,
        defense_on=defense is not None,
        results=results,
    )
