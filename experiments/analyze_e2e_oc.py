"""End-to-end structural gate on OPEN-MODEL traffic, parsed by Claude parsers
(results/parse_oc/{sonnet,haiku}; 'both' = conjunction). Sonnet-planner
authorization, deny-unknown, four argument policies. Benign cost is weighted by
occurrence over a stratified sample of distinct benign messages, with a cluster
bootstrap over user-request families. Writes results/e2e_oc_summary.json.
"""
from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

from analyze_e2e import decide, load_parses  # noqa: E402
from analyze_opencode import cls_of  # noqa: E402
from pivotbench.defense.registry import PRIVILEGED, TARGETS  # noqa: E402
from pivotbench.eval import wilson  # noqa: E402
from pivotbench.scenarios.gateaware import generate_gateaware  # noqa: E402
from pivotbench.scenarios.generator import generate_clean_pages, generate_everything  # noqa: E402


def main():
    scen = {s.id: s for s in generate_everything() + generate_gateaware() + generate_clean_pages()}
    key = json.loads((ROOT / "data" / "parse_oc" / "key.json").read_text())
    tasks = {t["request"]: t["id"] for t in json.loads((ROOT / "data" / "planner_v2" / "tasks_key.json").read_text())}
    out = {}
    for f in sorted((ROOT / "results" / "planner_v2" / "sonnet_s1").glob("batch_*.json")):
        for r in json.loads(f.read_text()):
            out[r["id"]] = (set(r.get("capabilities") or []), [str(a) for a in (r.get("args") or [])])
    table = {u: out.get(tid, (set(), [])) for u, tid in tasks.items()}
    P = {p: load_parses(ROOT / "results" / "parse_oc", p) for p in ("sonnet", "haiku")}
    res = {}
    rng = random.Random(29)
    for parser in ("sonnet", "haiku", "both"):
        names = ("sonnet", "haiku") if parser == "both" else (parser,)
        for policy in ("cap", "literal", "typed", "typed+"):
            cells = defaultdict(lambda: [0, 0])
            fam = defaultdict(lambda: [0, 0])
            why = defaultdict(int)
            for mid, info in key.items():
                if any(mid not in P[n] for n in names):
                    continue
                for occ in info["occurrences"]:
                    s = scen[occ["sid"]]
                    caps, vals = table.get(s.user_task, (set(), []))
                    w = ""
                    for n in names:
                        w = w or decide(P[n][mid], caps, vals, s.user_task, policy)
                    if occ["kind"] == "attack":
                        for c in dict.fromkeys((("attack_allowed", "all"), ("attack_allowed", cls_of(s)), ("attack_allowed", occ["model"]))):
                            cells[c][0] += int(not w)
                            cells[c][1] += 1
                    elif occ["kind"] == "refusal":
                        cells[("refusal_blocked", "all")][0] += int(bool(w))
                        cells[("refusal_blocked", "all")][1] += 1
                    else:
                        pc = "priv" if TARGETS.get(str(s.legit_target)) in PRIVILEGED else "nonpriv"
                        for c in dict.fromkeys((("benign_blocked", "all"), ("benign_blocked", occ["model"]), ("benign_blocked", pc))):
                            cells[c][0] += int(bool(w))
                            cells[c][1] += 1
                        fam[s.user_task][0] += int(bool(w))
                        fam[s.user_task][1] += 1
                        if w:
                            why[w.split(":")[0]] += 1
            row = {f"{a}|{b}": dict(zip(("k", "n", "p", "lo", "hi"), (k, n, *wilson(k, n)))) for (a, b), (k, n) in cells.items()}
            names_f = list(fam)
            boots = []
            for _ in range(2000):
                smp = [names_f[rng.randrange(len(names_f))] for _ in names_f]
                kk = sum(fam[t][0] for t in smp)
                nn = sum(fam[t][1] for t in smp)
                boots.append(kk / nn if nn else 0)
            boots.sort()
            row["benign_cluster"] = {"lo": boots[50], "hi": boots[1949], "families": len(names_f)}
            row["benign_reasons"] = dict(why)
            res[f"{parser}|{policy}"] = row
            b, a, rf = row.get("benign_blocked|all", {}), row.get("attack_allowed|all", {}), row.get("refusal_blocked|all", {})
            byc = {k.split("|")[1]: f"{v['k']}/{v['n']}" for k, v in row.items()
                   if k.startswith("attack_allowed|") and v["k"] and "|all" not in k}
            print(f"{parser:6s} {policy:7s} benign {b.get('k')}/{b.get('n')} ({b.get('p', 0)*100:.1f}% "
                  f"[{row['benign_cluster']['lo']*100:.1f},{row['benign_cluster']['hi']*100:.1f}]) "
                  f"attacks allowed {a.get('k')}/{a.get('n')} {byc} refusals blocked {rf.get('k')}/{rf.get('n')} why {dict(why)}")
    (ROOT / "results" / "e2e_oc_summary.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
