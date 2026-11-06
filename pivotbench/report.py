"""Render a SuiteResult to JSON and to a Markdown table."""
from __future__ import annotations

import json

from .harness import SuiteResult


def to_dict(suite: SuiteResult) -> dict:
    return {
        "model": suite.model,
        "defense_on": suite.defense_on,
        "summary": {
            "scenarios": suite.total,
            "attacks_fired": suite.attacks_fired,
            "attack_success_rate": round(suite.asr, 4),
            "blocked": suite.blocked,
            "block_rate": round(suite.block_rate, 4),
            "mean_defense_overhead_ms": round(suite.mean_overhead_ms, 4),
        },
        "results": [
            {
                "id": r.scenario_id,
                "title": r.title,
                "from": r.protocol_from,
                "to": r.protocol_to,
                "attack_fired": r.attack_fired,
                "blocked_by_defense": r.blocked_by_defense,
                "defense_overhead_ms": round(r.defense_overhead_ms, 4),
                "events": [str(e) for e in r.events],
            }
            for r in suite.results
        ],
    }


def to_json(suite: SuiteResult, indent: int = 2) -> str:
    return json.dumps(to_dict(suite), indent=indent)


def to_markdown(suite: SuiteResult) -> str:
    lines: list[str] = []
    defense = "ON" if suite.defense_on else "OFF"
    lines.append(f"### PivotBench — model=`{suite.model}`  defense={defense}")
    lines.append("")
    lines.append(
        f"**ASR {suite.asr:.0%}** ({suite.attacks_fired}/{suite.total})  ·  "
        f"blocked {suite.blocked}/{suite.total}  ·  "
        f"mean gate overhead {suite.mean_overhead_ms:.3f} ms"
    )
    lines.append("")
    lines.append("| Scenario | Pivot | Attack fired | Blocked | Gate ms |")
    lines.append("| --- | --- | :---: | :---: | ---: |")
    for r in suite.results:
        fired = "🔴 yes" if r.attack_fired else "🟢 no"
        blk = "🛡 yes" if r.blocked_by_defense else "—"
        lines.append(
            f"| `{r.scenario_id}` | {r.protocol_from}→{r.protocol_to} | "
            f"{fired} | {blk} | {r.defense_overhead_ms:.3f} |"
        )
    return "\n".join(lines)


def print_report(suite: SuiteResult) -> None:
    print(to_markdown(suite))
