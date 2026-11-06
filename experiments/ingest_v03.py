"""Validate and ingest v0.3 LLM decisions.

  results/llm/<model>_compliant/anon_batch_XX.json   (anonymized batches 00-11)
  results/llm/<model>_realistic/anon_rbatch_XX.json  (anonymized realistic batches)
Opaque case ids are mapped back via data/anon_idmap.json. In the realistic
condition, natural reference codes in payloads are mapped back to the scenario
canary so strict (canary) scoring applies unchanged.
Output: results/llm_decisions_v03.json  {condition: {scenario_id: {action, payload}}}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    idmap = json.loads((ROOT / "data" / "anon_idmap.json").read_text())
    meta = json.loads((ROOT / "data" / "realistic_meta.json").read_text())
    ref2can = meta["natural_ref_to_canary"]
    anon = ROOT / "data" / "llm_batches_anon"
    out, problems = {}, 0
    for cdir in sorted((ROOT / "results" / "llm").iterdir()):
        if not cdir.is_dir() or not cdir.name.endswith(("_compliant", "_realistic")):
            continue
        cond = cdir.name
        pattern = "anon_batch_*.json" if cond.endswith("_compliant") else "anon_rbatch_*.json"
        dec, st = {}, {"missing": 0, "extra": 0, "dup": 0, "bad": 0}
        for bf in sorted(anon.glob(pattern)):
            allowed = {x["id"] for x in json.loads(bf.read_text())}
            f = cdir / bf.name
            if not f.exists():
                st["missing"] += len(allowed)
                continue
            seen = set()
            for r in json.loads(f.read_text()):
                cid = r.get("id")
                if cid not in allowed:
                    st["extra"] += 1
                    continue
                if cid in seen:
                    st["dup"] += 1
                    continue
                seen.add(cid)
                act = r.get("action")
                if act not in ("escalate", "safe"):
                    st["bad"] += 1
                    act = "safe"
                payload = str(r.get("payload") or "")
                for ref, can in ref2can.items():
                    payload = payload.replace(ref, can)
                dec[idmap[cid]] = {"action": act, "payload": payload}
            st["missing"] += len(allowed - seen)
        out[cond] = dec
        problems += sum(st.values())
        n_esc = sum(d["action"] == "escalate" for d in dec.values())
        print(f"{cond:20s} decisions={len(dec):4d} escalate={n_esc:4d}" + ("" if not any(st.values()) else f"  <-- {st}"))
    (ROOT / "results" / "llm_decisions_v03.json").write_text(json.dumps(out, indent=1))
    return 1 if problems else 0




def reps() -> None:
    """Replicate runs of the compliant condition (results/llm_reps/<model>_compliant_repK/)."""
    idmap = json.loads((ROOT / "data" / "anon_idmap.json").read_text())
    out = {}
    base = ROOT / "results" / "llm_reps"
    for d in sorted(base.iterdir()) if base.exists() else []:
        dec = {}
        for f in sorted(d.glob("anon_batch_*.json")):
            allowed = {x["id"] for x in json.loads((ROOT / "data" / "llm_batches_anon" / f.name).read_text())}
            for r in json.loads(f.read_text()):
                if r.get("id") in allowed:
                    act = r.get("action") if r.get("action") in ("escalate", "safe") else "safe"
                    dec[idmap[r["id"]]] = {"action": act, "payload": str(r.get("payload") or "")}
        out[d.name] = dec
        print(f"{d.name:28s} decisions={len(dec):4d} escalate={sum(v['action'] == 'escalate' for v in dec.values()):4d}")
    (ROOT / "results" / "llm_decisions_reps.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    rc = main()
    reps()
    sys.exit(rc)
