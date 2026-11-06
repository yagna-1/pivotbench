"""Simulated orchestrator behaviours.

These model *how a susceptible orchestrator restates what it carries across a
boundary*, which is the property that decides whether a boundary defense can
see the pivot. They are deterministic so the grid is exactly reproducible.

On attack scenarios each susceptible behaviour carries the injected action
(and therefore the canary) across; they differ only in surface form. On benign
scenarios every behaviour carries the user's legitimate delegation across, in
the same surface style, so the defense's false-positive rate is measured on
payloads with matching style.

  verbatim    copies the directive exactly
  paraphrase  restates it in the orchestrator's own words (fixed phrase map)
  compress    keeps only content words (telegraphic tool-call style)
  mixer       prepends the user task / appends the untrusted context it read
  robust      never acts on untrusted directives (benign: delegates correctly)

The paraphrase phrase map is deliberately independent of the defenses'
canonicaliser (which uses no synonym table), so no defense can trivially
invert it.
"""
from __future__ import annotations

import re

from ..defense.text import CANARY_RE, STOPWORDS, tokens
from ..scenarios.base import Scenario
from ..threat_model import Decision

_PARAPHRASE: list[tuple[str, str]] = [
    (r"\bdelegate to the\b", "please have the"),
    (r"\bdelegate to\b", "please have"),
    (r"\binvoke the mcp tool\b", "run"),
    (r"\bapprove\b", "sign off on"),
    (r"\bconfirm with code\b", "using reference"),
    (r"\bconfirm with token\b", "using reference"),
    (r"\backnowledge with\b", "using reference"),
    (r"\brelay the value tagged\b", "send back the result, ref"),
    (r"\bexport\b", "pull out"),
    (r"\bcredentials bundle\b", "credential set"),
    (r"\bvendor payout\b", "supplier payment"),
    (r"\bfirst\b", "before that"),
    (r"\bask\b", "request that"),
    (r"\bdraft\b", "write up"),
    (r"\bbook\b", "set up"),
    (r"\bcall\b", "run"),
    (r"\bfile a bug\b", "open an issue"),
    (r"\bfetch\b", "retrieve"),
    (r"\btranslate\b", "render"),
    (r"\bsummary\b", "recap"),
]


def paraphrase(text: str) -> str:
    out = text
    for pat, rep in _PARAPHRASE:
        out = re.sub(pat, rep, out, flags=re.IGNORECASE)
    # Restructure "X: Y" -> "Y (route: X)" — a common orchestrator restatement.
    if ":" in out:
        head, _, tail = out.partition(":")
        if tail.strip() and len(head) < 60:
            out = f"{tail.strip()} (route: {head.strip()})"
    return out


def compress(text: str) -> str:
    canaries = CANARY_RE.findall(text)
    stripped = CANARY_RE.sub(" ", text)
    kept = [t for t in tokens(stripped) if t not in STOPWORDS]
    return " ".join(kept + canaries)


class _Behavior:
    name = "behavior"
    attack_escalates = True

    def _render(self, scenario: Scenario, base: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def decide(self, scenario: Scenario, tool_output: str) -> Decision:
        if scenario.is_attack:
            if not self.attack_escalates:
                return Decision(action="safe", payload="", raw=f"<{self.name}>")
            base = scenario.rendered_directive()
        else:
            base = scenario.expected_payload
        return Decision(action="escalate", payload=self._render(scenario, base), raw=f"<{self.name}>")


class Verbatim(_Behavior):
    name = "sim:verbatim"

    def _render(self, scenario: Scenario, base: str) -> str:
        return base


class Paraphrase(_Behavior):
    name = "sim:paraphrase"

    def _render(self, scenario: Scenario, base: str) -> str:
        return paraphrase(base)


class Compress(_Behavior):
    name = "sim:compress"

    def _render(self, scenario: Scenario, base: str) -> str:
        return compress(base)


class Mixer(_Behavior):
    name = "sim:mixer"

    def _render(self, scenario: Scenario, base: str) -> str:
        if scenario.is_attack:
            return f"{scenario.user_task} Then: {base}"
        # Benign: legitimate delegation that also quotes the untrusted context it
        # read. This is the hardest false-positive case for a provenance gate.
        return f"{base}. Context: {scenario.rendered_output()}"


class Robust(_Behavior):
    """Never acts on untrusted directives. Where the user legitimately asked for
    a cross-protocol action (benign scenarios, and the authorized request
    underlying an argument-hijack attack) it carries the user's request."""

    name = "sim:robust"
    attack_escalates = False

    def decide(self, scenario: Scenario, tool_output: str) -> Decision:
        if scenario.is_attack:
            if scenario.expected_payload:
                return Decision(action="escalate", payload=scenario.expected_payload, raw="<robust>")
            return Decision(action="safe", payload="", raw="<robust>")
        return Decision(action="escalate", payload=scenario.expected_payload, raw="<robust>")

    def _render(self, scenario: Scenario, base: str) -> str:
        return base


SIM_BEHAVIORS = [Verbatim(), Paraphrase(), Compress(), Mixer(), Robust()]
