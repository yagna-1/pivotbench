"""Validate and ingest LLM decision files into one canonical JSON.

Input : results/llm/<model>_<prompt>/batch_XX.json
Output: results/llm_decisions.json  {condition: {scenario_id: {action, payload}}}
        prints a validation table (missing / extra / duplicate / bad action)

Rules: only ids that belong to the corresponding batch are accepted; for a
duplicated id the first occurrence wins; anything other than
"escalate"/"safe" is normalised to "safe" and counted as bad.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    batches = {p.name: [x["id"] for x in json.loads(p.read_text())]
               for p in sorted((ROOT / "data" / "llm_batches").glob("batch_*.json"))}
    out: dict[str, dict] = {}
    problems = 0
    for cdir in sorted((ROOT / "results" / "llm").iterdir()):
        if not cdir.is_dir() or cdir.name.startswith("_"):
            continue
        cond = cdir.name
        decisions: dict[str, dict] = {}
        stats = {"missing": 0, "extra": 0, "dup": 0, "bad": 0}
        for bname, ids in batches.items():
            f = cdir / bname
            allowed = set(ids)
            if not f.exists():
                stats["missing"] += len(ids)
                continue
            rows = json.loads(f.read_text())
            seen = set()
            for r in rows:
                sid = r.get("id")
                if sid not in allowed:
                    stats["extra"] += 1
                    continue
                if sid in seen:
                    stats["dup"] += 1
                    continue
                seen.add(sid)
                act = r.get("action")
                if act not in ("escalate", "safe"):
                    stats["bad"] += 1
                    act = "safe"
                decisions[sid] = {"action": act, "payload": str(r.get("payload") or "")}
            stats["missing"] += len(allowed - seen)
        out[cond] = decisions
        n_esc = sum(d["action"] == "escalate" for d in decisions.values())
        flag = "" if not any(stats.values()) else f"  <-- {stats}"
        problems += sum(stats.values())
        print(f"{cond:18s} decisions={len(decisions):4d} escalate={n_esc:4d}{flag}")
    (ROOT / "results" / "llm_decisions.json").write_text(json.dumps(out, indent=1))
    print(f"wrote results/llm_decisions.json ({len(out)} conditions)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
