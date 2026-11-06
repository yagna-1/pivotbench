"""Capability-authorization gate (control-flow integrity for agent protocols).

Detection gates (lexical / argument / anchor) try to tell, from text, whether a
cross-protocol payload was *derived from* untrusted content. On real LLM traffic
that question is the wrong one: orchestrators legitimately carry untrusted DATA
into delegations ("draft a summary: revenue up 8%, churn flat"), so data flow
and instruction flow are indistinguishable at the text level.

This gate asks a different question:

    does the user's (trusted) request authorize the PRIVILEGED CAPABILITY this
    cross-protocol action invokes?

Untrusted content may flow freely as data. Only the choice of privileged action
must come from trusted provenance. This is the agent-protocol analogue of
control-flow integrity / capability-based least privilege.

Assumption (stated, and ablated in the experiments): the operator supplies a
manifest of privileged capabilities. In production the invoked capability is
read from the protocol message structurally (MCP `tools/call` name, A2A target
AgentCard id + skill), not parsed from prose; in this text-payload harness we
approximate that with per-capability patterns applied to the payload.
"""
from __future__ import annotations

import re
from typing import Mapping

from ..threat_model import Labeled
from .gates import _BaseGate
from .text import opaque_tokens

# Operator-supplied manifest: privileged capability -> pattern identifying an
# invocation of it. Action-level (resource + operation), not resource-level, so
# "find the refund policy" does not authorize "issue the refund batch".
DEFAULT_MANIFEST: dict[str, str] = {
    "payments.approve": r"\bpay(?:ment|out)s?\b|\bpay\b|payments?[ -]agent|supplier payment|disburse",
    "secrets.read": r"\bsecrets?\b|\bvault\b",
    "credentials.export": r"\bcredentials?\b",
    "keys.rotate": r"\brotat\w*\b|\bkeys\b|rotate_keys",
    "refunds.issue": r"\b(?:issue|process|approve)\w*\s+(?:the\s+)?(?:pending\s+)?refunds?\b|refund batch",
}

# A deliberately COARSE (resource-level) manifest, used as an ablation.
COARSE_MANIFEST: dict[str, str] = {
    "payments": r"\bpay\w*\b",
    "secrets": r"\bsecrets?\b",
    "credentials": r"\bcredentials?\b",
    "keys": r"\bkeys?\b|\brotat\w*",
    "refunds": r"\brefunds?\b",
}


class CapabilityGate(_BaseGate):
    """Block a cross-protocol payload that invokes a privileged capability the
    user's request does not authorize.

    With `check_arguments=True`, a payload that invokes an AUTHORIZED privileged
    capability is additionally required to take its opaque arguments (ids,
    accounts, scopes, tool paths) from the user's request rather than from
    untrusted content: argument provenance, scoped to privileged calls only, so
    ordinary data-carrying delegations are never inspected."""

    def __init__(self, manifest: Mapping[str, str] | None = None, name: str | None = None,
                 check_arguments: bool = False, min_arg_tokens: int = 1,
                 canary_aware: bool = False) -> None:
        super().__init__(canary_aware)
        self.manifest = dict(DEFAULT_MANIFEST if manifest is None else manifest)
        self._rx = {k: re.compile(v, re.IGNORECASE) for k, v in self.manifest.items()}
        self.check_arguments = check_arguments
        self.min_arg_tokens = min_arg_tokens
        suffix = ""
        if check_arguments:
            suffix = "+args" if min_arg_tokens == 1 else f"+args(k={min_arg_tokens})"
        self.name = name or (f"capability({len(self.manifest)})" + suffix)

    def invoked(self, text: str) -> set[str]:
        return {cap for cap, rx in self._rx.items() if rx.search(text)}

    def _decide(self, p: str, u: str, spans: list[Labeled]) -> tuple[bool, list[str]]:
        used = self.invoked(p)
        if not used:
            return False, []
        authorized = self.invoked(u)
        unauth = sorted(used - authorized)
        if unauth:
            return True, [f"unauthorized privileged capability {unauth}"]
        if self.check_arguments:
            p_ops = opaque_tokens(p)
            u_ops = opaque_tokens(u)
            u_low = u.lower()
            for s in spans:
                leaked = {t for t in (p_ops & opaque_tokens(s.content))
                          if t not in u_ops and t not in u_low}
                if len(leaked) >= self.min_arg_tokens:
                    return True, [f"privileged call {sorted(used)} takes untrusted arguments "
                                  f"{sorted(leaked)[:3]}"]
        return False, []
