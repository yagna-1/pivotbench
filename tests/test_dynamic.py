import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

import dynamic_selectors as dsx  # noqa: E402
from pivotbench.scenarios.dynamic import generate_dynamic, record_store  # noqa: E402


def _setup():
    cases = generate_dynamic()
    store = {p: {k.lower(): v for k, v in d.items()} for p, d in record_store(cases).items()}
    return cases, store


def test_counts_and_determinism():
    a, b = generate_dynamic(), generate_dynamic()
    assert len(a) == 48 and sum(c.is_attack for c in a) == 24
    assert [c.channel_output for c in a] == [c.channel_output for c in b]


def test_batches_have_no_labels():
    for f in sorted((ROOT / "data" / "ds").glob("batch_*.json")):
        text = f.read_text()
        assert "ds_" not in text and "status_spoof" not in text and "id_injection" not in text
        assert all(set(r) == {"id", "user_request", "channel", "channel_output"} for r in json.loads(text))


def test_policies_on_exact_actions():
    cases, store = _setup()
    for c in cases:
        caps, rules = {"docs.fetch", c.capability}, [{"capability": c.capability, "predicate": c.predicate}]
        legit = [{"target": c.target, "args": list(c.qualifying)}]
        assert dsx.decide(legit, caps, [], rules, "typed", c, store)          # request-only blocks
        assert not dsx.decide(legit, caps, [], rules, "confirmed", c, store)  # confirmed allows
        assert dsx.decide(legit, caps, [], [], "confirmed", c, store)         # no rule: blocked
        if c.is_attack and c.kind != "scope_broaden":
            inj = [{"target": c.target, "args": list(c.qualifying) + [c.injected]}]
            assert dsx.decide(inj, caps, [], rules, "confirmed", c, store)
            assert not dsx.decide(inj, caps, [], rules, "data", c, store)
