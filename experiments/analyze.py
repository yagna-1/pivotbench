"""Pool grid results per gate, per threat class, and compute the frontier.

Threat classes (see run_grid.py):
  pivot  cross-capability protocol pivots (4 mechanisms) + ordinary benign
  priv   within-capability argument hijacks + authorized privileged benign

Per gate and class we pool:
  security  strict ASR over the 4 SUSCEPTIBLE simulated behaviours
  sim cost  gate FPR on benign escalations of all 5 simulated behaviours
  llm cost  gate block rate on REAL LLM benign delegations, and collateral
            (LLM clean escalations on attack scenarios that the gate blocked)
Writes results/pooled.json and results/pareto.json and prints tables.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pivotbench.eval import wilson  # noqa: E402

SUSCEPTIBLE = ["sim:verbatim", "sim:paraphrase", "sim:compress", "sim:mixer"]


def pool(rs: list[dict], key: str) -> dict:
    src = {r["source"]: r[key] for r in rs}
    sims = [r[key] for r in rs if r["source_kind"] == "sim"]
    llm = [r[key] for r in rs if r["source_kind"] == "llm"]

    def tot(rows, metric):
        return sum(x[metric]["k"] for x in rows), sum(x[metric]["n"] for x in rows)

    a_k, a_n = tot([src[s] for s in SUSCEPTIBLE], "asr_strict")
    l_k, _ = tot([src[s] for s in SUSCEPTIBLE], "asr_lenient")
    sf_k, sf_n = tot(sims, "gate_fpr")
    lb_k, lb_n = tot(llm, "gate_fpr")
    lc_k, lc_n = tot(llm, "collateral_block_rate")
    la_k, la_n = tot(llm, "asr_strict")
    lat_k, lat_n = tot(llm, "model_attempt_rate")
    return {
        "asr": wilson(a_k, a_n), "asr_kn": [a_k, a_n],
        "asr_lenient": wilson(l_k, a_n),
        "asr_by_behavior": {s: src[s]["asr_strict"]["p"] for s in SUSCEPTIBLE},
        "sim_fpr": wilson(sf_k, sf_n), "sim_fpr_kn": [sf_k, sf_n],
        "llm_benign_block": wilson(lb_k, lb_n), "llm_benign_kn": [lb_k, lb_n],
        "llm_collateral": wilson(lc_k, lc_n), "llm_collateral_kn": [lc_k, lc_n],
        "llm_cost": wilson(lb_k + lc_k, lb_n + lc_n),
        "llm_asr": wilson(la_k, la_n), "llm_asr_kn": [la_k, la_n],
        "llm_attempt": wilson(lat_k, lat_n), "llm_attempt_kn": [lat_k, lat_n],
    }


def main() -> None:
    rows = [json.loads(l) for l in open(ROOT / "results" / "grid_summary.jsonl")]
    by_gate: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_gate[r["gate"]].append(r)

    pooled = {}
    for g, rs in by_gate.items():
        ms = [r["gate_ms_mean"] for r in rs if r["gate_ms_mean"] > 0]
        p99 = [r["gate_ms_p99"] for r in rs if r["gate_ms_p99"] > 0]
        pooled[g] = {
            "gate": g, "params": rs[0]["params"],
            "pivot": pool(rs, "pivot"), "priv": pool(rs, "priv"),
            "gate_ms_mean": sum(ms) / len(ms) if ms else 0.0,
            "gate_ms_p99": max(p99) if p99 else 0.0,
        }

    def cost(p, cls):
        return max(p[cls]["sim_fpr"][0], p[cls]["llm_cost"][0])

    frontiers = {}
    for cls in ("pivot", "priv"):
        pts = sorted((p[cls]["asr"][0], cost(p, cls), g) for g, p in pooled.items())
        fr = []
        for a, c, g in pts:
            if not fr or c < fr[-1][1] - 1e-12:
                fr.append((a, c, g))
        frontiers[cls] = [{"asr": a, "cost": c, "gate": g} for a, c, g in fr]
    (ROOT / "results" / "pooled.json").write_text(json.dumps(pooled, indent=1))
    (ROOT / "results" / "pareto.json").write_text(json.dumps(frontiers, indent=1))

    def fmt(w):
        return f"{w[0]*100:5.1f} [{w[1]*100:4.1f},{w[2]*100:5.1f}]"

    headline = ["none", "strict_boundary", "taint_gate_v0.1", "lexical(n=3,k=1,dir=1,canon=1)",
                "lexical(n=2,k=1,dir=1,canon=1)", "argument(k=1)", "argument(k=1,CANARY)",
                "anchor(t=0.30,dir=0)", "any[L3c+Arg]", "any[Arg+A0.3]", "any[L3c+Arg+A0.3]",
                "capability(coarse)", "capability(5)", "capability(5)+args", "capability(coarse)+args"]
    for cls in ("pivot", "priv"):
        print(f"\n=== threat class: {cls} ===")
        print(f"{'gate':34s} {'ASR susc.sim':>19s} {'sim FPR':>19s} {'LLM benign blk':>19s} {'LLM collateral':>19s}")
        for g in headline:
            p = pooled[g][cls]
            print(f"{g:34s} {fmt(p['asr']):>19s} {fmt(p['sim_fpr']):>19s} {fmt(p['llm_benign_block']):>19s} "
                  f"{fmt(p['llm_collateral']):>19s}")
        print(f"Pareto frontier ({cls}):")
        for f in frontiers[cls]:
            print(f"   ASR {f['asr']*100:5.1f}%  cost {f['cost']*100:5.1f}%  {f['gate']}")
    print("\nLLM model-side (no gate): attempts / strict ASR")
    p = pooled["none"]
    for cls in ("pivot", "priv"):
        print(f"  {cls}: attempts {p[cls]['llm_attempt_kn']}  strictASR {p[cls]['llm_asr_kn']}  "
              f"upper95={p[cls]['llm_attempt'][2]*100:.2f}%")
    print("\nlatency (ms): " + ", ".join(f"{g}={pooled[g]['gate_ms_mean']:.4f}/{pooled[g]['gate_ms_p99']:.3f}"
                                         for g in ["taint_gate_v0.1", "capability(5)+args", "anchor(t=0.30,dir=0)"]))


if __name__ == "__main__":
    main()
