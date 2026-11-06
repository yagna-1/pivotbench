"""v0.1 reference gate, kept for API compatibility.

`TaintGate` is now a preset of `LexicalTaintGate` (raw 4-gram overlap with an
untrusted span, directive-shaped payloads only, canary-blind). See gates.py for
the full defense family evaluated in v0.2.
"""
from __future__ import annotations

from .gates import GateResult, LexicalTaintGate


class TaintGate(LexicalTaintGate):
    def __init__(self, ngram: int = 4, min_overlap: int = 1) -> None:
        super().__init__(n=ngram, min_overlap=min_overlap,
                         require_directive=True, canonicalize=False)
        self.name = "taint_gate_v0.1"


__all__ = ["TaintGate", "GateResult"]
