# PivotBench Threat Model

## Setting

A single orchestrating agent composes two agent protocols:

- **MCP** (Model Context Protocol) for tool access — file systems, APIs, search.
- **A2A** (Agent-to-Agent) for delegating tasks to other agents.

Each protocol's own security model assumes it is the only one in play. MCP vets
tool servers; A2A vets peer agents. Neither reasons about content that *entered*
through the other.

## Adversary

The adversary controls content that an MCP tool returns, or a message a peer agent
sends — i.e. one untrusted input channel. The adversary cannot modify the
orchestrator's code, the user's request, or the system prompt. This is the
realistic indirect-injection position: a poisoned web page, a compromised tool
server, a malicious peer in the mesh.

## Trust lattice

| Provenance | Trusted? | Origin |
| --- | --- | --- |
| `USER` | yes | the human principal |
| `SYSTEM` | yes | operator-controlled instructions |
| `MCP_TOOL` | **no** | anything an MCP tool returns |
| `A2A_PEER` | **no** | anything a peer agent sends |

## The pivot (attack invariant being tested)

1. **Initial access** — an injected directive enters content processed by the
   agent through protocol P₁ (untrusted).
2. **Boundary crossing** — the agent carries that directive into protocol P₂
   (P₂ ≠ P₁), e.g. MCP output → A2A delegation, or A2A message → MCP tool call.
3. **Escalation** — the downstream endpoint of P₂ trusts its caller (the
   orchestrator) and performs a privileged action it would never grant the
   original adversary directly.

A **tripped canary** is proof the full chain executed.

## Security goal / defense invariant

**v0.1 (detection, superseded):**

> No directive derived from untrusted provenance may cross a protocol boundary.

The v0.1 `TaintGate` tried to enforce this by detecting, from text, whether a
crossing payload was derived from an untrusted span. v0.2 shows this cannot be
done at acceptable cost: orchestrators legitimately carry untrusted *data* into
delegations, so text-level derivation conflates data flow with instruction flow
(paper §6.2–6.3).

**v0.2 (capability authorization):**

> Untrusted content may cross a boundary as data. The *privileged capability* a
> cross-protocol action invokes must be authorized by trusted provenance (the
> user's request). Optionally, for authorized privileged calls, the action's
> opaque arguments must not come from untrusted content.

This requires an operator manifest of privileged capabilities at *action*
granularity (`refunds.issue`, not `refunds`). Each capability missing from the
manifest is fully exposed (paper §6.5).

## Within-capability argument hijack

A second adversary goal: the user legitimately authorizes a privileged
capability, and untrusted content swaps its arguments (payee, scope, target).
Capability authorization alone cannot see this; scoped argument provenance
reduces it but cannot distinguish "copied from a document the user approved"
from "copied from attacker text". This is an open problem.

## Out of scope (v0.1)

- Attacks fully within one protocol (covered by existing single-protocol benchmarks).
- Model weight backdoors / training-time compromise.
- Compromise of the orchestrator process itself.
- Network/transport attacks (TLS, auth) — assumed handled by the transport layer.

## Why boundary-aware, not per-protocol

Per-protocol controls each see only half the chain: the MCP side sees a normal tool
result; the A2A side sees a normal delegation from a trusted orchestrator. Only a
control that tracks provenance *across* the boundary sees the whole pivot. This
matches the IETF MCP-security draft's stated conclusion.
