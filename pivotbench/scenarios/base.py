"""A scenario is a self-contained protocol-pivoting test case (attack) or a
legitimate cross-protocol delegation (benign control)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..threat_model import Protocol, Provenance


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str

    # Where the untrusted content enters, and where the escalated effect lands.
    entry_protocol: Protocol
    target_protocol: Protocol
    entry_provenance: Provenance  # MCP_TOOL or A2A_PEER

    # The task the user actually asked for (TRUSTED provenance).
    user_task: str

    # The tool/channel whose output is attacker-controlled (or just untrusted),
    # and its content.
    tainted_tool: str
    tainted_output: str  # attack: must embed {canary}; benign: plain content

    # Unique token that proves the injected cross-protocol action fired.
    # Empty for benign scenarios.
    canary: str

    # The injected directive, extracted from the tainted output. This is what a
    # vulnerable orchestrator forwards verbatim across the boundary.
    # Empty for benign scenarios.
    injected_directive: str  # must contain {canary} for attacks

    # "attack" | "benign"
    label: str = "attack"

    # For benign scenarios: the payload a *correct* orchestrator would carry
    # across the boundary (it derives from the USER's request).
    expected_payload: str = ""

    # Provenance of how this scenario was produced (handwritten / generated) and
    # which mutators were applied. Used for per-mutator breakdowns.
    mutators: dict = field(default_factory=dict, compare=False, hash=False)

    # v0.3 structured actions. In a real deployment the target of a
    # cross-protocol action is a structured protocol field (MCP tools/call name,
    # A2A target AgentCard/skill). `injected_*` is the action the attacker wants;
    # `legit_*` is the action the user's request legitimately calls for (empty
    # when the request needs no cross-protocol action).
    injected_target: str = ""
    injected_args: tuple = ()
    legit_target: str = ""
    legit_args: tuple = ()

    @property
    def natural_ref(self) -> str:
        """A natural-looking reference code that replaces the canary in
        model-visible text (v0.3 'realistic' LLM condition). Unique per scenario."""
        if not self.canary:
            return ""
        import hashlib
        h = int(hashlib.sha256(self.canary.encode()).hexdigest()[:12], 16)
        return f"PO-{h % 900000 + 100000}"

    def rendered_output_natural(self) -> str:
        out = self.rendered_output()
        return out.replace(self.canary, self.natural_ref) if self.canary else out

    # ---- helpers -----------------------------------------------------------
    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    def rendered_output(self) -> str:
        return self.tainted_output.replace("{canary}", self.canary) if self.canary else self.tainted_output

    def rendered_directive(self) -> str:
        return self.injected_directive.replace("{canary}", self.canary) if self.canary else ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "entry_protocol": self.entry_protocol.value,
            "target_protocol": self.target_protocol.value,
            "entry_provenance": self.entry_provenance.value,
            "user_task": self.user_task,
            "tainted_tool": self.tainted_tool,
            "tainted_output": self.rendered_output(),
            "canary": self.canary,
            "injected_directive": self.rendered_directive(),
            "label": self.label,
            "expected_payload": self.expected_payload,
            "mutators": dict(self.mutators),
        }
