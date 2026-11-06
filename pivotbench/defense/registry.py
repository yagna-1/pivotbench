"""Capability registry and structured actions (v0.3).

In MCP and A2A the target of an action is a STRUCTURED field: the MCP
`tools/call` name, or the A2A target agent (AgentCard) and skill. A boundary
gate can read it without parsing prose. This module models that:

  * TARGETS maps a target identity (tool name or agent/skill id) to the
    capability it exercises; the registry marks which capabilities are
    privileged.
  * Action is the structured form of a cross-protocol action: target id plus
    named argument values.

Anything not in TARGETS is UNKNOWN. A deny-by-default gate blocks unknown
targets; a fail-open gate lets them through.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# capability -> (privileged?, description used by the intent planner)
CAPABILITIES: dict[str, tuple[bool, str]] = {
    "payments.approve": (True, "approve or send a payment, payout, or invoice payment"),
    "secrets.read": (True, "read secrets, passwords, or credentials from a secret store"),
    "credentials.export": (True, "export or bundle stored credentials or login tokens"),
    "keys.rotate": (True, "rotate, reissue, or revoke API keys or access keys"),
    "refunds.issue": (True, "issue or process a customer refund"),
    "comms.draft": (False, "draft an email or message"),
    "calendar.book": (False, "book or schedule a meeting"),
    "orders.status": (False, "look up the status of an order"),
    "translate.render": (False, "translate a document"),
    "crm.lookup": (False, "look up a CRM record"),
    "triage.file_bug": (False, "file a bug or issue"),
    "docs.fetch": (False, "fetch, read, search, or summarize documents, pages, tickets, notes, calendars"),
}

PRIVILEGED = frozenset(c for c, (p, _) in CAPABILITIES.items() if p)

# target identity (as it appears in the protocol message) -> capability
TARGETS: dict[str, str] = {
    "a2a:payments-agent/approve": "payments.approve",
    "mcp:secrets.read": "secrets.read",
    "a2a:ops-agent/export-credentials": "credentials.export",
    "mcp:infra.rotate_keys": "keys.rotate",
    "a2a:finance-agent/issue-refund": "refunds.issue",
    "a2a:comms-agent/draft": "comms.draft",
    "a2a:scheduling-agent/book": "calendar.book",
    "mcp:orders.status": "orders.status",
    "a2a:translation-agent/render": "translate.render",
    "mcp:crm.lookup": "crm.lookup",
    "a2a:triage-agent/file-bug": "triage.file_bug",
    "mcp:docs.fetch": "docs.fetch",
}


@dataclass(frozen=True)
class Action:
    """A structured cross-protocol action."""

    target: str                      # e.g. "a2a:payments-agent/approve"
    args: tuple[tuple[str, str], ...] = field(default=())

    @property
    def capability(self) -> str | None:
        return TARGETS.get(self.target)

    def arg_values(self) -> set[str]:
        return {v for _, v in self.args}
