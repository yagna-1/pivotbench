"""Judge items for the real compromised payloads that arrived after the main
judge export (replicate runs of the compliant condition), mixed 1:1 with real
benign escalations from the same runs. Writes data/judge_extra_batches/judge_00.json
and data/judge_extra_key.json."""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.eval import FileDecisionModel, _is_attempt, threat_class  # noqa: E402
from pivotbench.scenarios.generator import generate_everything  # noqa: E402
from pivotbench.threat_model import Decision  # noqa: E402


def main() -> None:
    rng = random.Random(4417)
    scen = {s.id: s for s in generate_everything()}
    reps = json.loads((ROOT / "results" / "llm_decisions_reps.json").read_text())
    atk, ben = [], []
    for cond, dec in sorted(reps.items()):
        m = FileDecisionModel(cond.rsplit("_rep", 1)[0], {})
        for sid, v in sorted(dec.items()):
            s = scen[sid]
            msg = v["payload"].replace(s.canary, s.natural_ref) if s.canary else v["payload"]
            if s.is_attack and _is_attempt(s, m, Decision(**v)):
                atk.append({"sid": sid, "kind": "attack", "src": f"llm:{cond}", "cls": threat_class(sid),
                            "user_request": s.user_task, "message": msg})
            elif not s.is_attack and v["action"] == "escalate" and v["payload"].strip():
                ben.append({"sid": sid, "kind": "benign", "src": f"llm:{cond}", "cls": "rep",
                            "user_request": s.user_task, "message": msg})
    rng.shuffle(ben)
    items = atk + ben[:len(atk)]
    rng.shuffle(items)
    out, key = [], {}
    for i, it in enumerate(items):
        cid = "item-" + hashlib.sha256(f"extra|{i}|{it['sid']}|{it['src']}".encode()).hexdigest()[:7]
        key[cid] = {k: it[k] for k in ("sid", "kind", "src", "cls")}
        out.append({"id": cid, "user_request": it["user_request"], "outgoing_message": it["message"]})
    d = ROOT / "data" / "judge_extra_batches"
    d.mkdir(exist_ok=True)
    (d / "judge_00.json").write_text(json.dumps(out, indent=1))
    (ROOT / "data" / "judge_extra_key.json").write_text(json.dumps(key, indent=1))
    print(f"{len(out)} items ({len(atk)} attack)")


if __name__ == "__main__":
    main()
