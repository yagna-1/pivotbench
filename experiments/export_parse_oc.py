"""Export open-model outgoing messages for structural parsing (Claude parsers).

All attempted attack payloads, all adjudicated refusals (legitimate actions on
attack pages that quote the attacker's values), and a stratified random sample
of 600 distinct benign messages (150 per model). Natural reference codes stay as
the models wrote them. Writes data/parse_oc/parse_XX.json and key.json.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

from analyze_opencode import OC, flag  # noqa: E402
from pivotbench.scenarios.gateaware import generate_gateaware  # noqa: E402
from pivotbench.scenarios.generator import generate_clean_pages, generate_everything  # noqa: E402


def main():
    scen = {s.id: s for s in generate_everything() + generate_gateaware() + generate_clean_pages()}
    idmap = json.loads((ROOT / "data" / "r2_idmap.json").read_text())
    adj = {(a["run"], a["scenario_id"]) for a in json.loads((ROOT / "data" / "adjudication_opencode.json").read_text())["items"]}
    att, ref, ben = {}, {}, {}
    for mdir in sorted(p for p in OC.iterdir() if p.is_dir()):
        for cond in ("realistic", "mixed_rep1", "mixed_rep2", "mixed_rep3", "single"):
            for f in sorted((mdir / cond).glob("*.json")) if (mdir / cond).exists() else []:
                run = f"{mdir.name}/{cond}/{f.stem}"
                for r in json.loads(f.read_text()):
                    p = str(r.get("payload") or "").strip() if r.get("action") == "escalate" else ""
                    if not p:
                        continue
                    s = scen[idmap[r["id"]]]
                    occ = {"sid": s.id, "run": run, "model": mdir.name}
                    if s.is_attack:
                        if flag(s, p):
                            (ref if (run, s.id) in adj else att).setdefault(p, []).append(occ)
                    else:
                        ben.setdefault(mdir.name, {}).setdefault(p, []).append(occ)
    rng = random.Random(23)
    items, key = [], {}
    def add(msg, occs, kind):
        mid = "oc-" + hashlib.sha256(msg.encode()).hexdigest()[:8]
        if mid in key:
            key[mid]["occurrences"] += [{**o, "kind": kind} for o in occs]
            return
        key[mid] = {"message": msg, "occurrences": [{**o, "kind": kind} for o in occs]}
        items.append({"id": mid, "message": msg})
    for m, o in att.items():
        add(m, o, "attack")
    for m, o in ref.items():
        add(m, o, "refusal")
    for model, d in sorted(ben.items()):
        msgs = sorted(d)
        rng.shuffle(msgs)
        for m in msgs[:150]:
            add(m, d[m], "benign")
    rng.shuffle(items)
    out = ROOT / "data" / "parse_oc"
    out.mkdir(exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    for b, i in enumerate(range(0, len(items), 50)):
        (out / f"parse_{b:02d}.json").write_text(json.dumps(items[i:i + 50], indent=1))
    (out / "key.json").write_text(json.dumps(key, indent=1))
    print(f"attack {len(att)} distinct, refusal {len(ref)}, benign sample {sum(min(150, len(d)) for d in ben.values())} "
          f"(of {sum(len(d) for d in ben.values())} distinct); {len(items)} items, {(len(items) + 49) // 50} batches")


if __name__ == "__main__":
    main()
