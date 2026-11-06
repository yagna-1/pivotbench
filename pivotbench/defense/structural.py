"""Structural capability-authorization gate (v0.3).

Formal model (paper §4.2)
-------------------------
  A cross-protocol action is a = (t, args): a target identity t (MCP tools/call
  name, or A2A AgentCard + skill) and argument values.
  R: T -> C is the registry mapping target identities to capabilities;
  P ⊆ C is the set of privileged capabilities (the manifest).
  Auth(u) ⊆ C and End(u) are the capabilities and argument values authorized
  by the trusted user request u, computed WITHOUT reading untrusted content.

  Gate(a, u) = BLOCK  if t ∉ dom(R) and mode ∈ {deny_unknown, allowlist}
             = BLOCK  if mode = allowlist and R(t) ∉ Auth(u)
             = BLOCK  if R(t) ∈ P and R(t) ∉ Auth(u)
             = BLOCK  if R(t) ∈ P and check_args and vals(args) ⊄ End(u)
             = ALLOW  otherwise.

Authorization sources (how Auth/End are obtained) are pluggable:
  oracle   ground truth per user request (upper bound)
  planner  an LLM that reads ONLY the user request (CaMeL-style planning)
  prose    the v0.2 regex matcher applied to the user's text (ablation)
"""
from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

from ..threat_model import AuditEvent, Labeled, Protocol
from .gates import GateResult
from .registry import PRIVILEGED, TARGETS, Action

AuthFn = Callable[[str], tuple[set, set]]  # user_task -> (capabilities, endorsed arg values)

MODES = ("fail_open", "deny_unknown", "allowlist")


class StructuralGate:
    def __init__(self, auth: AuthFn, mode: str = "deny_unknown", check_args: bool = True,
                 privileged: Iterable[str] = PRIVILEGED, registry: dict | None = None,
                 name: str | None = None) -> None:
        assert mode in MODES, mode
        self.auth = auth
        self.mode = mode
        self.check_args = check_args
        self.privileged = frozenset(privileged)
        self.registry = TARGETS if registry is None else registry
        self.name = name or f"structural({mode}{',args' if check_args else ''})"

    def decide(self, action: Action, user_task: str) -> tuple[bool, str]:
        cap = self.registry.get(action.target)
        if cap is None:
            if self.mode in ("deny_unknown", "allowlist"):
                return True, f"unknown target {action.target}"
            return False, ""
        caps, endorsed = self.auth(user_task)
        if self.mode == "allowlist" and cap not in caps:
            return True, f"capability {cap} not authorized"
        if cap in self.privileged:
            if cap not in caps:
                return True, f"privileged capability {cap} not authorized"
            if self.check_args:
                vals = action.arg_values()
                bad = sorted(v for v in vals if v not in endorsed)
                if bad:
                    return True, f"privileged arguments {bad} not endorsed by the user"
        return False, ""

    def check(self, *, payload: str, user_task: str, untrusted_spans: list[Labeled],
              protocol_from: Protocol, protocol_to: Protocol,
              action: Optional[Action] = None, **_) -> GateResult:
        t0 = time.perf_counter()
        if protocol_from == protocol_to:
            block, why = False, ""
        elif action is None:
            # no structured action could be resolved: fail closed unless fail-open
            block, why = (self.mode != "fail_open"), "no structured action"
        else:
            block, why = self.decide(action, user_task)
        ms = (time.perf_counter() - t0) * 1000.0
        ev = AuditEvent(kind="blocked" if block else "allowed", detail=f"{self.name}: {why or 'cleared'}",
                        protocol_from=protocol_from, protocol_to=protocol_to)
        return GateResult(allowed=not block, event=ev, latency_ms=ms, reasons=[why] if why else [])


# --------------------------------------------------------------------------- auth sources
def prose_auth() -> AuthFn:
    """v0.2 regex matcher on the user's own text (the ablation R2 criticised)."""
    from .capability import CapabilityGate
    from .text import opaque_tokens
    g = CapabilityGate()

    def fn(u: str) -> tuple[set, set]:
        caps = g.invoked(u)
        # non-privileged capabilities are never prose-detected; grant the generic lookup
        caps = set(caps) | {"docs.fetch"}
        vals = set(opaque_tokens(u)) | {w.strip(".,;:!?()'\"") for w in u.split()}
        return caps, vals
    return fn


def table_auth(table: dict[str, tuple[Iterable[str], Iterable[str]]], default=(("docs.fetch",), ())) -> AuthFn:
    def fn(u: str) -> tuple[set, set]:
        caps, vals = table.get(u, default)
        return set(caps), set(vals)
    return fn
