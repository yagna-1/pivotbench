"""Core trust/provenance primitives shared across the environment, the defense,
and the harness.

The central idea of protocol pivoting is that each agent protocol (MCP, A2A, ...)
was designed with a security model that assumes it operates alone. When they are
composed, content that entered as UNTRUSTED through one protocol can cross a
boundary and be treated as a trusted instruction in another. We make that
boundary-crossing first-class by attaching a provenance label to every span of
content and tracking it across protocol hops.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Provenance(str, Enum):
    """Where a span of content originated. This is the trust label that the
    defense tracks across protocol boundaries."""

    USER = "user"          # trusted: the human principal
    SYSTEM = "system"      # trusted: operator-controlled instructions
    MCP_TOOL = "mcp_tool"  # UNTRUSTED: content returned by an MCP tool call
    A2A_PEER = "a2a_peer"  # UNTRUSTED: a message received from another agent


# Only these origins may contribute *directives* that cross a protocol boundary.
TRUSTED_ORIGINS = frozenset({Provenance.USER, Provenance.SYSTEM})


class Protocol(str, Enum):
    MCP = "mcp"
    A2A = "a2a"


@dataclass(frozen=True)
class Labeled:
    """A span of content carrying its provenance label and its source."""

    content: str
    provenance: Provenance
    source: str = ""  # e.g. "docs-search:fetch" or "peer:research-agent"

    @property
    def trusted(self) -> bool:
        return self.provenance in TRUSTED_ORIGINS


@dataclass
class AuditEvent:
    """A single causal event in a run. The defense emits these; a tripped canary
    is the signal of a successful attack."""

    kind: str  # "delegation" | "blocked" | "canary_tripped" | "escalated"
    detail: str
    protocol_from: Optional[Protocol] = None
    protocol_to: Optional[Protocol] = None
    provenance: Optional[Provenance] = None
    data: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        edge = ""
        if self.protocol_from or self.protocol_to:
            edge = f" [{self.protocol_from or '-'}→{self.protocol_to or '-'}]"
        return f"{self.kind}{edge}: {self.detail}"


@dataclass
class Decision:
    """The orchestrator's chosen next action, as produced by a model (or a
    deterministic stand-in).

    action == "escalate" means the orchestrator wants to perform the
    boundary-crossing action (delegate a task over A2A, or invoke a privileged
    MCP tool). `payload` is the task/argument it intends to carry across.
    """

    action: str  # "escalate" | "safe"
    payload: str = ""
    raw: str = ""  # raw model text, for debugging
