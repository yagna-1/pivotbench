"""Attenuable delegation tokens for multi-hop authorization (round-2 revision).

Macaroon-style chained HMAC (Birgisson et al., NDSS 2014). The orchestrator's
gate holds the root key and mints a token from the ORIGINAL user request:

    sig_0 = HMAC(root_key, nonce)
    sig_i = HMAC(sig_{i-1}, caveat_i)

Caveats are first-order predicates the verifier must all satisfy:
    task=<id>            binds the token to one user task (anti-replay across tasks)
    aud=<agent>          only this downstream agent may present it
    cap=<c1,c2,...>      privileged capabilities usable under the token
    val=<v1|v2|...>      endorsed argument values (typed: digit-bearing ids and
                         scope-broadening words such as 'all' that the user said)
    exp=<int>            logical expiry (hop counter or time)
    use=once             single use: the verifier records the token nonce and
                         refuses a second presentation (stateful)

Anyone holding a token can APPEND caveats (attenuate) without the key, because
the new signature is HMAC(old_sig, caveat). Nobody can remove or edit a caveat
without the root key, so a compromised intermediate agent can only narrow its
authority. Every caveat of a given kind must hold, so two cap= caveats give the
intersection.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

BROAD = {"all", "every", "fleet", "org", "global", "*", "everyone", "entire"}


def _h(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def digit_tokens(text: str) -> set:
    return {t for t in re.findall(r"[a-z0-9][a-z0-9._/@:-]*", str(text).lower()) if any(c.isdigit() for c in t)}


@dataclass(frozen=True)
class Token:
    nonce: str
    caveats: tuple = ()
    sig: bytes = b""

    def attenuate(self, caveat: str) -> "Token":
        return Token(self.nonce, self.caveats + (caveat,), _h(self.sig, caveat))

    def serialize(self) -> str:
        return "|".join([self.nonce, *self.caveats, self.sig.hex()])


@dataclass
class Minter:
    root_key: bytes
    _n: int = field(default=0)

    def mint(self, task: str, audience: str, caps, values, exp: int = 2, once: bool = False) -> Token:
        self._n += 1
        t = Token(f"n{self._n}", (), _h(self.root_key, f"n{self._n}"))
        t = t.attenuate(f"task={task}").attenuate(f"aud={audience}")
        t = t.attenuate("cap=" + ",".join(sorted(caps)))
        endorsed = set()
        for v in values or []:
            endorsed |= digit_tokens(v) | {w for w in re.findall(r"[a-z*]+", str(v).lower()) if w in BROAD}
        t = t.attenuate("val=" + "|".join(sorted(endorsed)))
        t = t.attenuate(f"exp={exp}")
        return t.attenuate("use=once") if once else t


@dataclass
class Verifier:
    root_key: bytes
    privileged: frozenset
    spent: set = field(default_factory=set)

    def check(self, token: Token | None, *, task: str, audience: str, cap: str, args, hop: int) -> str:
        """Return '' if the action is allowed, else the reason it is blocked."""
        if cap not in self.privileged:
            return ""
        if token is None:
            return "no-token"
        sig = _h(self.root_key, token.nonce)
        for c in token.caveats:
            sig = _h(sig, c)
        if not hmac.compare_digest(sig, token.sig):
            return "bad-signature"
        kinds = {}
        for c in token.caveats:
            k, _, v = c.partition("=")
            kinds.setdefault(k, []).append(v)
        for need in ("task", "aud", "cap", "val", "exp"):
            if need not in kinds:
                return f"missing-{need}"
        if any(v != task for v in kinds["task"]):
            return "wrong-task"
        if any(v != audience for v in kinds["aud"]):
            return "wrong-audience"
        if any(hop > int(v) for v in kinds["exp"]):
            return "expired"
        if any(cap not in set(filter(None, v.split(","))) for v in kinds["cap"]):
            return "capability"
        vals = [set(filter(None, v.split("|"))) for v in kinds["val"]]
        argtxt = " ".join(str(a) for a in (args or []))
        for d in digit_tokens(argtxt):
            if any(d not in vs for vs in vals):
                return "value"
        for w in {w for w in re.findall(r"[a-z*]+", argtxt.lower()) if w in BROAD}:
            if any(w not in vs for vs in vals):
                return "value-scope"
        if "use" in kinds:
            if token.nonce in self.spent:
                return "spent"
            self.spent.add(token.nonce)
        return ""
