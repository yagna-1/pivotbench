"""Multi-hop authorization with attenuable tokens (round-2 revision).

Two-hop chain: orchestrator --A2A--> downstream agent --MCP--> privileged tool.
The orchestrator's gate mints a token (pivotbench/defense/token.py) from the
ORIGINAL user request: task binding, audience = the agent it delegates to,
cap = Auth(u), val = typed endorsed values of End(u). The token travels in the
orchestration layer, never in model-visible text. The downstream gate verifies
it before any privileged action.

Adversaries, each run on every attack scenario whose injected action is
privileged (all threat classes and gate-aware classes):
  stateless     no token; hop 2 trusts its caller (confused deputy)
  carried-set   v0.3 baseline: hop 2 checks cap in Auth(u), no arguments
  inject        honest hop 1 forwards the injected request with the real token
  forge         injected text carries a token-shaped string claiming the cap
  replay        token minted for a different task whose request DID authorize
                the injected capability
  widen         compromised hop 1 appends cap=<injected cap> to the real token
  strip         compromised hop 1 drops the cap caveat from the real token
  wrong-aud     the real token presented by a different agent
  insider       compromised hop 1 acts within its token: injected cap with the
                injected arguments; residual = what Auth(u) x End(u) permits
  repeat        compromised hop 1 repeats the user's OWN authorized action
                (e.g. pays the authorized invoice twice); run on the benign
                privileged requests, without and with a use=once caveat
Benign: every user-authorized privileged request, with the user's own values,
under oracle and planner authorization. Writes results/multihop_v2.json.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pivotbench.defense.intent import oracle_table  # noqa: E402
from pivotbench.defense.registry import PRIVILEGED, TARGETS  # noqa: E402
from pivotbench.defense.token import Minter, Token, Verifier  # noqa: E402
from pivotbench.eval import threat_class, wilson  # noqa: E402
from pivotbench.scenarios.gateaware import generate_gateaware  # noqa: E402
from pivotbench.scenarios.generator import generate_clean_pages, generate_everything  # noqa: E402


def agent_of(target: str) -> str:
    return target.split(":", 1)[1].split("/")[0] if target.startswith("a2a:") else "tool-runner"


def main() -> None:
    key = os.urandom(32)
    minter, ver = Minter(key), Verifier(key, frozenset(PRIVILEGED))
    scen = generate_everything() + generate_gateaware()
    allsc = scen + generate_clean_pages()
    oracle = {u: (set(c), list(v)) for u, (c, v) in oracle_table(allsc).items()}
    tasks = {t["request"]: t["id"] for t in json.loads((ROOT / "data" / "planner_v2" / "tasks_key.json").read_text())}

    def planner_tab(run):
        out = {}
        for f in sorted((ROOT / "results" / "planner_v2" / run).glob("batch_*.json")):
            for r in json.loads(f.read_text()):
                out[r["id"]] = (set(r.get("capabilities") or []), [str(a) for a in (r.get("args") or [])])
        return {u: out.get(tid, (set(), [])) for u, tid in tasks.items()}

    auths = {"oracle": oracle, "planner:sonnet": planner_tab("sonnet_s1"), "planner:haiku": planner_tab("haiku_s1")}
    # a donor task for replay: any user request whose authorization includes the capability
    donors = defaultdict(list)
    for u, (caps, vals) in oracle.items():
        for c in caps:
            donors[c].append((u, vals))

    res = {}
    for aname, table in auths.items():
        cells = defaultdict(lambda: [0, 0])
        why = defaultdict(lambda: defaultdict(int))
        for s in scen:
            if not s.is_attack or not s.injected_target:
                continue
            cap = TARGETS.get(s.injected_target)
            if cap is None or cap not in PRIVILEGED:
                continue
            cls = ("gateaware:" + s.mutators["gateaware"]) if s.id.startswith("gen_gateaware") else threat_class(s.id)
            caps_u, vals_u = table.get(s.user_task, (set(), []))
            task, aud = f"t:{s.user_task}", agent_of(s.legit_target or s.injected_target)
            tok = minter.mint(task, aud, caps_u, vals_u)
            args = [str(v) for _, v in s.injected_args]
            outcomes = {
                "stateless": "",
                "carried-set": "" if cap in caps_u else "capability",
                "inject": ver.check(tok, task=task, audience=aud, cap=cap, args=args, hop=1),
                "forge": ver.check(Token("n0", (f"task={task}", f"aud={aud}", f"cap={cap}", "val=" + "|".join(args), "exp=9"),
                                         os.urandom(32)), task=task, audience=aud, cap=cap, args=args, hop=1),
                "widen": ver.check(tok.attenuate(f"cap={cap}"), task=task, audience=aud, cap=cap, args=args, hop=1),
                "strip": ver.check(Token(tok.nonce, tuple(c for c in tok.caveats if not c.startswith(("cap=", "val="))), tok.sig),
                                   task=task, audience=aud, cap=cap, args=args, hop=1),
                "wrong-aud": ver.check(tok, task=task, audience="mallory-agent", cap=cap, args=args, hop=1),
                "insider": ver.check(tok, task=task, audience=aud, cap=cap, args=args, hop=1),
            }
            dn = [d for d in donors.get(cap, []) if d[0] != s.user_task]
            if dn:
                du, dv = dn[0]
                dtok = minter.mint(f"t:{du}", aud, {cap}, dv + args)
                outcomes["replay"] = ver.check(dtok, task=task, audience=aud, cap=cap, args=args, hop=1)
            for adv, w in outcomes.items():
                for c in ((adv, cls), (adv, "all")):
                    cells[c][0] += int(not w)
                    cells[c][1] += 1
                if w:
                    why[adv][w] += 1
        # benign: user-authorized privileged requests with the user's own values
        ben = [0, 0]
        bwhy = defaultdict(int)
        rep = {False: [0, 0], True: [0, 0]}
        for s in allsc:
            if s.is_attack or not s.legit_target:
                continue
            cap = TARGETS.get(s.legit_target)
            if cap is None or cap not in PRIVILEGED:
                continue
            caps_u, vals_u = table.get(s.user_task, (set(), []))
            task, aud = f"t:{s.user_task}", agent_of(s.legit_target)
            tok = minter.mint(task, aud, caps_u, vals_u)
            w = ver.check(tok, task=task, audience=aud, cap=cap, args=[str(v) for _, v in s.legit_args], hop=1)
            ben[0] += int(bool(w))
            ben[1] += 1
            if w:
                bwhy[w] += 1
            a = [str(v) for _, v in s.legit_args]
            for once in (False, True):
                t2 = minter.mint(task, aud, caps_u, vals_u, once=once)
                first = ver.check(t2, task=task, audience=aud, cap=cap, args=a, hop=1)
                second = ver.check(t2, task=task, audience=aud, cap=cap, args=a, hop=1)
                if not first:
                    rep[once][0] += int(not second)
                    rep[once][1] += 1
        row = {}
        for (adv, cls), (k, n) in sorted(cells.items()):
            p, lo, hi = wilson(k, n)
            row[f"{adv}|{cls}"] = {"k": k, "n": n, "p": p, "lo": lo, "hi": hi}
        p, lo, hi = wilson(*ben)
        row["benign_blocked"] = {"k": ben[0], "n": ben[1], "p": p, "lo": lo, "hi": hi, "why": dict(bwhy)}
        row["block_reasons"] = {a: dict(d) for a, d in why.items()}
        for once, (k, n) in rep.items():
            p, lo, hi = wilson(k, n)
            row["repeat_allowed|" + ("use_once" if once else "no_use_caveat")] = {"k": k, "n": n, "p": p, "lo": lo, "hi": hi}
        print(f"  repeat (2nd use allowed): no use-caveat {rep[False][0]}/{rep[False][1]}, use=once {rep[True][0]}/{rep[True][1]}")
        res[aname] = row
        print(f"== {aname}: benign blocked {ben[0]}/{ben[1]} {dict(bwhy)}")
        for adv in ("stateless", "carried-set", "inject", "forge", "replay", "widen", "strip", "wrong-aud", "insider"):
            k, n = cells[(adv, "all")]
            per = {c: f"{v[0]}/{v[1]}" for (a, c), v in cells.items() if a == adv and c != "all" and v[0]}
            print(f"  {adv:12s} allowed {k}/{n}  nonzero {per}")
    (ROOT / "results" / "multihop_v2.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
