"""The orchestrator ties a model to the environment, with an optional defense.

Flow per scenario:
  1. Call the (mock) MCP/A2A channel -> UNTRUSTED Labeled output.
  2. Ask the model for its next action (escalate | safe) + payload.
  3. If a defense is attached, run it on the intended cross-protocol action
     BEFORE it crosses the boundary. A blocked action never reaches the sink.
  4. If allowed and the model chose to escalate, perform the boundary-crossing
     action against the SensitiveAction sink, propagating any canary the
     payload carries.
"""
from __future__ import annotations

from typing import Optional

from ..defense.gates import Gate, GateResult
from ..env import SensitiveAction
from ..scenarios.base import Scenario
from ..threat_model import AuditEvent, Decision, Labeled
from .model_adapter import Model


class Orchestrator:
    def __init__(self, model: Model, defense: Optional[Gate] = None) -> None:
        self.model = model
        self.defense = defense
        self.last_decision: Optional[Decision] = None

    def run(self, scenario: Scenario, action_sink: SensitiveAction, action=None) -> list[AuditEvent]:
        events: list[AuditEvent] = []

        tool_output = Labeled(
            content=scenario.rendered_output(),
            provenance=scenario.entry_provenance,
            source=scenario.tainted_tool,
        )

        decision: Decision = self.model.decide(scenario, tool_output.content)
        self.last_decision = decision

        if decision.action != "escalate" or not decision.payload.strip():
            events.append(AuditEvent(kind="safe", detail="orchestrator did not escalate",
                                     provenance=tool_output.provenance))
            return events

        if self.defense is not None:
            result: GateResult = self.defense.check(
                payload=decision.payload,
                user_task=scenario.user_task,
                untrusted_spans=[tool_output],
                protocol_from=scenario.entry_protocol,
                protocol_to=scenario.target_protocol,
                action=action(decision) if callable(action) else action,
            )
            result.event.data["latency_ms"] = result.latency_ms
            events.append(result.event)
            if not result.allowed:
                return events  # fail closed: sink never reached

        canary = scenario.canary if (scenario.canary and scenario.canary in decision.payload) else None
        events.append(action_sink.invoke(decision.payload, canary))
        return events
