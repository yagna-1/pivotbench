"""A minimal, in-process stand-in for an MCP tool server.

It returns tool results as UNTRUSTED `Labeled` content. In a pivoting scenario
the result carries attacker-planted text that is shaped like an instruction for a
*different* protocol (e.g. an A2A task). No network, no real tools — the payload
for each tool is set by the scenario.
"""
from __future__ import annotations

from ..threat_model import Labeled, Provenance


class MockMCPServer:
    def __init__(self, name: str = "docs-search") -> None:
        self.name = name
        self._payloads: dict[str, str] = {}

    def set_payload(self, tool: str, content: str) -> None:
        """Register what a given tool returns (the scenario plants the attack here)."""
        self._payloads[tool] = content

    def call_tool(self, tool: str, arguments: dict | None = None) -> Labeled:
        content = self._payloads.get(tool, f"(no data for tool={tool!r})")
        # Everything an MCP tool returns is external, attacker-reachable content.
        return Labeled(
            content=content,
            provenance=Provenance.MCP_TOOL,
            source=f"{self.name}:{tool}",
        )
