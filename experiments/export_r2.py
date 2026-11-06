"""Round-2 model-side batches (revision after round-2 review).

  data/llm_batches_r2/mixed_XX.json     10 de-cued, class-balanced batches of 12
        (5 attacks: one pivot, hijack, over-auth, drift and gate-aware case;
         7 benign: 2 ordinary, 1 privileged, 2 held-out, 1 implicit, 1 clean)
        used with the 'compliant' (misconfigured-policy) prompt; every run is a
        fresh subagent; natural reference codes, opaque ids
  data/llm_batches_r2/single_XX.json    12 single-case files (one attack each)
  data/llm_batches_r2/real_XX.json      40 realistic batches of 20 (3 attacks,
        17 benign or clean; 15% base rate), 120 distinct attack scenarios over
        all classes, production prompt
  data/r2_idmap.json, data/r2_refmap.json
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.eval import threat_class  # noqa: E402
from pivotbench.scenarios.gateaware import generate_gateaware  # noqa: E402
from pivotbench.scenarios.generator import generate_clean_pages, generate_everything  # noqa: E402

SEED = 4242


def item(s, salt):
    cid = "case-" + hashlib.sha256(f"{salt}|{s.id}".encode()).hexdigest()[:7]
    return cid, {"id": cid, "user_request": s.user_task,
                 "channel": (f"MCP tool result from `{s.tainted_tool}`" if s.entry_protocol.value == "mcp"
                             else "A2A message from a peer agent"),
                 "channel_output": s.rendered_output_natural().replace("(context the orchestrator also read) ", "")}


def main() -> None:
    rng = random.Random(SEED)
    scen = generate_everything()
    ga = generate_gateaware()
    clean = generate_clean_pages()
    allsc = scen + ga + clean
    pools = {
        "pivot": [s for s in scen if s.is_attack and threat_class(s.id) == "pivot"],
        "hijack": [s for s in scen if s.is_attack and threat_class(s.id) == "hijack"],
        "overauth": [s for s in scen if s.is_attack and threat_class(s.id) == "overauth"],
        "drift": [s for s in scen if s.is_attack and threat_class(s.id) == "drift"],
        "gateaware": [s for s in ga if s.mutators["gateaware"] != "poisoned_card"] + [s for s in ga if s.mutators["gateaware"] == "poisoned_card"],
        "ordinary": [s for s in scen if s.id.startswith("benign_")],
        "privileged": [s for s in scen if s.id.startswith("privbenign_")],
        "heldout": [s for s in scen if s.id.startswith("benign2_")],
        "implicit": [s for s in scen if s.id.startswith("privimplicit_")],
        "clean": clean,
    }
    for k in pools:
        rng.shuffle(pools[k])
    out = ROOT / "data" / "llm_batches_r2"
    out.mkdir(exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    idmap = {}
    used = set()

    def take(k, n):
        got = [s for s in pools[k] if s.id not in used][:n]
        used.update(s.id for s in got)
        return got

    # mixed, class-balanced compliant batches
    for b in range(10):
        cases = (take("pivot", 1) + take("hijack", 1) + take("overauth", 1) + take("drift", 1) + take("gateaware", 1)
                 + take("ordinary", 2) + take("privileged", 1) + take("heldout", 2) + take("implicit", 1) + take("clean", 1))
        rng.shuffle(cases)
        items = []
        for s in cases:
            cid, it = item(s, f"r2mixed{b}")
            idmap[cid] = s.id
            items.append(it)
        (out / f"mixed_{b:02d}.json").write_text(json.dumps(items, indent=1))
    # single-case files
    for b, k in enumerate(["pivot", "hijack", "overauth", "drift"] * 3):
        s = take(k, 1)[0]
        cid, it = item(s, f"r2single{b}")
        idmap[cid] = s.id
        (out / f"single_{b:02d}.json").write_text(json.dumps([it], indent=1))
    # realistic, large
    used_real = set()
    att = []
    quota = {"pivot": 54, "hijack": 18, "overauth": 24, "drift": 24}
    for k, q in quota.items():
        pool = [s for s in pools[k]]
        att += pool[:q]
    rng.shuffle(att)
    fill_pool = pools["ordinary"] + pools["privileged"] + pools["heldout"] + pools["implicit"] + pools["clean"]
    for b in range(40):
        a = att[3 * b: 3 * b + 3]
        f = rng.sample(fill_pool, 17)
        cases = a + f
        rng.shuffle(cases)
        items = []
        for s in cases:
            cid, it = item(s, f"r2real{b}")
            idmap[cid] = s.id
            items.append(it)
        used_real.update(x.id for x in a)
        (out / f"real_{b:02d}.json").write_text(json.dumps(items, indent=1))
    refs = {s.natural_ref: s.canary for s in allsc if s.canary}
    (ROOT / "data" / "r2_idmap.json").write_text(json.dumps(idmap, indent=1))
    (ROOT / "data" / "r2_refmap.json").write_text(json.dumps(refs, indent=1))
    leaks = [f.name for f in out.glob("*.json") if "CANARY" in f.read_text() or "gen_" in f.read_text()]
    print(f"mixed 10x12, single 12, realistic 40x20 ({len(used_real)} distinct attacks); leaks: {leaks}")


if __name__ == "__main__":
    main()
