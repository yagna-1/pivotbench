"""Cluster-bootstrap robustness check.

Wilson intervals treat scenarios as independent, but scenarios share templates:
each pivot mechanism is repeated across 12 content domains, and each benign
task family across 8 context/quote variants. Here we resample whole CLUSTERS:
  * pivot ASR        : clusters = content domains (12), susceptible sims pooled
  * real benign cost : clusters = benign task families (6 ordinary + 3 privileged)
2,000 resamples, percentile 95% intervals. Writes results/bootstrap.json.
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUSC = {"sim:verbatim", "sim:paraphrase", "sim:compress", "sim:mixer"}
GATES = ["none", "taint_gate_v0.1", "lexical(n=3,k=1,dir=1,canon=1)", "argument(k=1)",
         "anchor(t=0.30,dir=0)", "any[L3c+Arg+A0.3]", "capability(coarse)", "capability(5)",
         "capability(5)+args(k=2)"]
B = 2000


def main() -> None:
    asr = defaultdict(lambda: defaultdict(lambda: [0, 0]))   # gate -> cover -> [k, n]
    cost = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # gate -> family -> [blocked, escalated]
    for line in open(ROOT / "results" / "grid_records.jsonl"):
        r = json.loads(line)
        g = r["gate"]
        if g not in GATES:
            continue
        sid = r["scenario_id"]
        if r["source"] in SUSC and r["label"] == "attack" and not sid.startswith("gen_arghijack_"):
            c = asr[g][r["mutators"]["cover"]]
            c[0] += int(r["strict_success"])
            c[1] += 1
        if not r["source"].startswith("sim:") and r["label"] == "benign" and r["escalated"]:
            c = cost[g][r["mutators"]["base"]]
            c[0] += int(r["blocked"])
            c[1] += 1

    rng = random.Random(7)

    def boot(clusters: dict) -> dict:
        keys = sorted(clusters)
        k = sum(clusters[x][0] for x in keys)
        n = sum(clusters[x][1] for x in keys)
        stats = []
        for _ in range(B):
            samp = [rng.choice(keys) for _ in keys]
            kk = sum(clusters[x][0] for x in samp)
            nn = sum(clusters[x][1] for x in samp)
            stats.append(kk / nn if nn else 0.0)
        stats.sort()
        return {"p": k / n if n else float("nan"), "lo": stats[int(0.025 * B)],
                "hi": stats[int(0.975 * B) - 1], "clusters": len(keys), "n": n}

    out = {g: {"pivot_asr": boot(asr[g]), "llm_benign_block": boot(cost[g])} for g in GATES}
    (ROOT / "results" / "bootstrap.json").write_text(json.dumps(out, indent=1))
    print(f"{'gate':34s} {'pivot ASR (cluster=domain)':>30s} {'real benign blocked (cluster=task)':>36s}")
    for g, v in out.items():
        a, c = v["pivot_asr"], v["llm_benign_block"]
        print(f"{g:34s} {a['p']*100:6.1f} [{a['lo']*100:5.1f},{a['hi']*100:5.1f}] k={a['clusters']:2d}   "
              f"{c['p']*100:6.1f} [{c['lo']*100:5.1f},{c['hi']*100:5.1f}] k={c['clusters']}")


if __name__ == "__main__":
    main()
