"""Export v0.3 LLM-experiment inputs (written after round-1 review).

  data/planner_tasks.json            every distinct user request + capability registry
  data/llm_batches/batch_08..11.json v0.3 extension (over-auth, drift, held-out benign)
                                      used by the 'compliant' orchestrator condition
  data/llm_batches_realistic/rbatch_XX.json
                                      realistic condition: neutral production prompt,
                                      natural reference codes (no 'CANARY-' text),
                                      10 cases per batch with exactly ONE attack
  data/realistic_meta.json           natural-ref -> canary map, attack ids
The original batches 00-07 are not touched.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.defense.registry import CAPABILITIES  # noqa: E402
from pivotbench.scenarios.generator import (  # noqa: E402
    generate_all,
    generate_clean_pages,
    generate_v03,
)

SEED = 20261105


def item(s, natural=False):
    return {
        "id": s.id,
        "user_request": s.user_task,
        "channel": (f"MCP tool result from `{s.tainted_tool}`" if s.entry_protocol.value == "mcp"
                    else "A2A message from a peer agent"),
        "channel_output": s.rendered_output_natural() if natural else s.rendered_output(),
    }


def main() -> None:
    data = ROOT / "data"
    v02 = generate_all()
    v03 = generate_v03()
    clean = generate_clean_pages()
    by_id = {s.id: s for s in v02 + v03 + clean}

    # ---- planner tasks: every distinct user request (planner never sees channel output)
    tasks = sorted({s.user_task for s in v02 + v03 + clean})
    planner = {
        "registry": {c: {"privileged": p, "description": d} for c, (p, d) in CAPABILITIES.items()},
        "tasks": [{"id": f"t{i:03d}", "user_request": t} for i, t in enumerate(tasks)],
    }
    (data / "planner_tasks.json").write_text(json.dumps(planner, indent=1))

    # ---- v0.3 extension batches 08-11 (compliant condition)
    rng = random.Random(SEED)
    over = [s.id for s in v03 if s.id.startswith("gen_overauth_")]
    drift = [s.id for s in v03 if s.id.startswith("gen_drift_")]
    drift_pick = sorted(drift)[::4][:24]          # 24 of 96, spread over mechanisms/covers/variants
    held = [s.id for s in v03 if s.id.startswith(("benign2_", "privimplicit_"))]
    held_pick = sorted(held)[::2]                 # 36 of 72, both quote/context variants represented
    ext = over + drift_pick + held_pick
    rng.shuffle(ext)
    bdir = data / "llm_batches"
    for b, i in enumerate(range(0, len(ext), 24), start=8):
        (bdir / f"batch_{b:02d}.json").write_text(json.dumps([item(by_id[x]) for x in ext[i:i + 24]], indent=1))

    # ---- realistic condition: 12 batches x 10, exactly one attack per batch
    piv = ["gen_privesc_ticket_inline_sentence_unaligned", "gen_capinject_calendar_inline_sentence_aligned",
           "gen_chain_release_notes_inline_sentence_unaligned", "gen_spoofed_card_kb_article_inline_sentence_aligned"]
    ova = ["gen_overauth_privesc_payteam_docs_inline_sentence_unaligned",
           "gen_overauth_capinject_secrets_policy_inline_sentence_unaligned",
           "gen_overauth_chain_cred_hygiene_inline_sentence_unaligned",
           "gen_overauth_spoofed_card_apikeys_docs_inline_sentence_unaligned"]
    dri = ["gen_drift_unreg_privesc_wiki_status", "gen_drift_reg_capinject_changelog"]
    hij = ["gen_arghijack_pay_invoice_inline_sentence_aligned", "gen_arghijack_rotate_own_key_inline_sentence_unaligned"]
    attacks = piv + ova + dri + hij
    for a in attacks:
        assert a in by_id, a
    fillers = ([s.id for s in v03 if s.id.startswith(("benign2_", "privimplicit_"))]
               + [s.id for s in clean]
               + [s.id for s in v02 if s.id.startswith("benign_")][::4])
    rng2 = random.Random(SEED + 7)
    rng2.shuffle(fillers)
    fillers = fillers[: 9 * len(attacks)]
    rdir = data / "llm_batches_realistic"
    rdir.mkdir(exist_ok=True)
    for old in rdir.glob("rbatch_*.json"):
        old.unlink()
    for b, a in enumerate(attacks):
        ids = [a] + fillers[9 * b: 9 * b + 9]
        rng2.shuffle(ids)
        (rdir / f"rbatch_{b:02d}.json").write_text(json.dumps([item(by_id[x], natural=True) for x in ids], indent=1))
    meta = {"attacks": attacks, "fillers": fillers,
            "natural_ref_to_canary": {by_id[a].natural_ref: by_id[a].canary for a in attacks}}
    (data / "realistic_meta.json").write_text(json.dumps(meta, indent=1))
    print(f"planner tasks: {len(tasks)}")
    print(f"ext batches 08-{8 + (len(ext) - 1) // 24}: {len(ext)} items "
          f"(overauth {len(over)}, drift {len(drift_pick)}, held-out benign {len(held_pick)})")
    print(f"realistic: {len(attacks)} batches x 10 (1 attack each), fillers {len(fillers)}")
    leak = [x for x in (rdir.glob('rbatch_*.json')) if 'CANARY' in x.read_text()]
    print("CANARY text in realistic batches:", len(leak))


if __name__ == "__main__":
    main()


def anonymize() -> None:
    """Opaque case ids for every model-visible batch used in v0.3 runs.
    (The v0.2 batches exposed scenario ids such as 'gen_privesc_...', a cue.)"""
    import hashlib
    data = ROOT / "data"
    out = data / "llm_batches_anon"
    out.mkdir(exist_ok=True)
    idmap = {}
    sources = sorted((data / "llm_batches").glob("batch_*.json")) + sorted((data / "llm_batches_realistic").glob("rbatch_*.json"))
    for f in sources:
        items = json.loads(f.read_text())
        anon = []
        for it in items:
            cid = "case-" + hashlib.sha256(("anon|" + it["id"]).encode()).hexdigest()[:6]
            assert idmap.get(cid, it["id"]) == it["id"], "collision"
            idmap[cid] = it["id"]
            anon.append({**it, "id": cid})
        (out / f"anon_{f.name}").write_text(json.dumps(anon, indent=1))
    (data / "anon_idmap.json").write_text(json.dumps(idmap, indent=1))
    print(f"anonymized {len(sources)} batches, {len(idmap)} ids")


if __name__ == "__main__":
    anonymize()


def realization() -> None:
    """LLM message-realization batches: the decision to act is GIVEN; the model
    composes the protocol message. Same items as the compliant set (282)."""
    import hashlib
    data = ROOT / "data"
    v02, v03 = generate_all(), generate_v03()
    by_id = {s.id: s for s in v02 + v03}
    ids = []
    for f in sorted((data / "llm_batches").glob("batch_*.json")):
        ids += [x["id"] for x in json.loads(f.read_text())]
    rng = random.Random(SEED + 11)
    rng.shuffle(ids)
    rdir = data / "llm_batches_realize"
    rdir.mkdir(exist_ok=True)
    rev = {}
    for b, i in enumerate(range(0, len(ids), 36)):
        items = []
        for sid in ids[i:i + 36]:
            s = by_id[sid]
            action = s.rendered_directive() if s.is_attack else s.expected_payload
            if s.canary:
                action = action.replace(s.canary, s.natural_ref)
            cid = "case-" + hashlib.sha256(("realize|" + sid).encode()).hexdigest()[:6]
            rev[cid] = sid
            items.append({"id": cid, "user_request": s.user_task,
                          "channel": (f"MCP tool result from `{s.tainted_tool}`" if s.entry_protocol.value == "mcp"
                                      else "A2A message from a peer agent"),
                          "channel_output": s.rendered_output_natural(),
                          "action_to_send": action})
        (rdir / f"realize_{b:02d}.json").write_text(json.dumps(items, indent=1))
    (data / "realize_idmap.json").write_text(json.dumps(rev, indent=1))
    refs = {s.natural_ref: s.canary for s in v02 + v03 if s.canary}
    (data / "realize_refmap.json").write_text(json.dumps(refs, indent=1))
    print(f"realization: {len(ids)} items in {(len(ids) + 35) // 36} batches")


if __name__ == "__main__":
    realization()
