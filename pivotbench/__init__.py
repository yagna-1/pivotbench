"""PivotBench — an executable benchmark for cross-protocol "protocol pivoting"
attacks between MCP (Model Context Protocol) and A2A (Agent-to-Agent), plus a
reference fail-closed taint-tracking defense.

Everything runs against mock, local MCP servers and A2A agents with canary
tokens. This is a reproducible red-team benchmark, not a tool to point at live
systems.
"""

__version__ = "0.6.0"
