"""Export the full scenario catalog and build the paired LLM evaluation batches.

Outputs
  data/scenarios.jsonl            full catalog (handwritten v0.1 + generated v0.2)
  data/llm_subset_ids.json        stratified subset used for LLM-in-the-loop runs
  data/llm_batches/batch_XX.json  orchestrator-visible fields only, shuffled

The LLM subset is stratified so every mechanism, cover domain, alignment and
injection position is represented:
  attacks : 4 mechanisms x 12 covers x 2 alignments = 96, with the injection
            position rotated across covers (32 per position)
  benign  : all 48
The SAME batches are used for every model/prompt condition (paired design), so
conditions can be compared with McNemar's test.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.scenarios import SCENARIOS, generate_all  # noqa: E402
from pivotbench.scenarios.generator import COVERS, INJECT_POSITIONS, MECHANISMS  # noqa: E402

SEED = 20261104
BATCH_SIZE = 24


def main() -> None:
    data = ROOT / "data"
    data.mkdir(exist_ok=True)

    generated = generate_all()
    handwritten = [s for s in SCENARIOS]
    with open(data / "scenarios.jsonl", "w", encoding="utf-8") as fh:
        for s in handwritten:
            d = s.to_dict()
            d["source"] = "handwritten_v0.1"
            fh.write(json.dumps(d) + "\n")
        for s in generated:
            d = s.to_dict()
            d["source"] = "generated_v0.2"
            fh.write(json.dumps(d) + "\n")

    by_id = {s.id: s for s in generated}
    positions = list(INJECT_POSITIONS)
    subset: list[str] = []
    for mi, mech in enumerate(MECHANISMS):
        for ci, cover in enumerate(COVERS):
            pos = positions[(ci + mi) % len(positions)]
            for align in ("unaligned", "aligned"):
                sid = f"gen_{mech.key}_{cover.key}_{pos}_{align}"
                assert sid in by_id, sid
                subset.append(sid)
    # v0.2 subset: the original 48 benign controls only (ids "benign_*"). Kept
    # byte-identical to the batches the LLM runs were made on.
    subset += [s.id for s in generated if s.id.startswith("benign_")]

    rng = random.Random(SEED)
    order = subset[:]
    rng.shuffle(order)

    # v0.2b extension: argument hijacks + authorized privileged delegations,
    # appended as NEW batches so earlier batches are untouched.
    ext = [s.id for s in generated if s.id.startswith(("gen_arghijack_", "privbenign_"))]
    rng_ext = random.Random(SEED + 1)
    rng_ext.shuffle(ext)
    n_v02 = len(order)
    order_all = order + ext
    (data / "llm_subset_ids.json").write_text(json.dumps(order_all, indent=1))

    bdir = data / "llm_batches"
    bdir.mkdir(exist_ok=True)
    for old in bdir.glob("batch_*.json"):
        old.unlink()
    chunks = [order[i : i + BATCH_SIZE] for i in range(0, n_v02, BATCH_SIZE)]
    half = (len(ext) + 1) // 2
    chunks += [ext[:half], ext[half:]]
    n_batches = 0
    for b, ids in enumerate(chunks):
        items = []
        for sid in ids:
            s = by_id[sid]
            items.append({
                "id": s.id,
                "user_request": s.user_task,
                "channel": (f"MCP tool result from `{s.tainted_tool}`"
                            if s.entry_protocol.value == "mcp"
                            else "A2A message from a peer agent"),
                "channel_output": s.rendered_output(),
            })
        (bdir / f"batch_{b:02d}.json").write_text(json.dumps(items, indent=1))
        n_batches += 1

    n_att = sum(by_id[i].label == "attack" for i in order_all)
    print(f"catalog: {len(handwritten)} handwritten + {len(generated)} generated")
    print(f"llm subset: {len(order_all)} ({n_att} attack, {len(order_all) - n_att} benign) "
          f"-> {n_batches} batches of <= {BATCH_SIZE}")


if __name__ == "__main__":
    main()
