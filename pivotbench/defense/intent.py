"""Authorization sources for the structural gate: Auth(u) and End(u).

  oracle   ground truth: the capabilities and argument values that the user's
           request legitimately calls for, read off the scenario definitions
           (an upper bound: perfect intent extraction)
  planner  the output of an LLM planner that saw ONLY the user's request
           (results/planner/<model>.json), as in CaMeL-style planning
  prose    the v0.2 regex matcher applied to the user's text (see structural.py)
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ..scenarios.base import Scenario
from .registry import TARGETS
from .structural import AuthFn, table_auth

ROOT = Path(__file__).resolve().parents[2]


def oracle_table(scenarios: Iterable[Scenario]) -> dict[str, tuple[set, set]]:
    caps: dict[str, set] = defaultdict(lambda: {"docs.fetch"})
    vals: dict[str, set] = defaultdict(set)
    for s in scenarios:
        u = s.user_task
        caps[u]  # ensure key
        if s.legit_target:
            cap = TARGETS.get(s.legit_target)
            if cap:
                caps[u].add(cap)
            vals[u] |= {v for _, v in s.legit_args}
    return {u: (caps[u], vals[u]) for u in caps}


def oracle_auth(scenarios: Iterable[Scenario]) -> AuthFn:
    return table_auth(oracle_table(scenarios))


def planner_table(model: str) -> dict[str, tuple[set, set]]:
    tasks = json.loads((ROOT / "data" / "planner_tasks.json").read_text())["tasks"]
    out = json.loads((ROOT / "results" / "planner" / f"{model}.json").read_text())
    by_id = {t["id"]: t["user_request"] for t in tasks}
    table = {}
    for tid, u in by_id.items():
        rec = out.get(tid, {"capabilities": [], "args": []})
        table[u] = (set(rec.get("capabilities", [])), {str(a) for a in rec.get("args", [])})
    return table


def planner_auth(model: str) -> AuthFn:
    return table_auth(planner_table(model), default=((), ()))
