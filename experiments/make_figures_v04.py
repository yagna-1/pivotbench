"""v0.4 figures (round-2 revision).

fig9_checks.png    what each boundary check costs on real benign traffic and how
                   many attack items it lets through, by family of check
fig8_compliance_runs.png  (rebuilt) run-level compliance under the misconfigured
                   policy, v0.3 runs plus round-2 class-balanced, de-cued runs
Same light surface and palette as the earlier figures. Every value is printed
next to its mark, so nothing depends on colour alone.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIG = ROOT / "paper" / "figures"
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA, YELLOW, GRAY = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#8a8984"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 10.5, "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
})


def wilson(k, n, z=1.959964):
    if n == 0:
        return 0, 0, 0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0, c - h), min(1, c + h)


def fig_checks():
    A = json.loads((ROOT / "results" / "v03_analysis.json").read_text())["gates"]
    R2 = json.loads((ROOT / "results" / "r2_analysis.json").read_text())
    CL = R2["cluster"]
    JD = R2["judges"]
    E = json.loads((ROOT / "results" / "e2e_summary.json").read_text())
    rows = []  # (label, family, benign p, lo, hi, n_benign, attack k, attack n, attack set)

    def gate(label, key, fam):
        c = CL[key]
        s = A[key]["sim_asr"]["all"]
        rows.append((label, fam, c["p"], c["lo"], c["hi"], "1,160", s["k"], s["n"], "sim", ""))

    gate("lexical taint (n=4)", "taint_gate_v0.1", "heur")
    gate("lexical n=2, canon.", "lexical(n=2,k=1,dir=1,canon=1)", "heur")
    gate("argument taint", "argument(k=1)", "heur")
    gate("anchor t=0.3", "anchor(t=0.30,dir=0)", "heur")
    gate("lexical + arg. + anchor", "any[L3c+Arg+A0.3]", "heur")
    gate("prose capability", "capability(5)", "heur")
    for label, key, fam in (("data-provenance judge", "prov_data", "llmdet"),
                            ("instruction-provenance judge", "prov_instr", "llmdet"),
                            ("injection classifier", "pi", "llmdet"),
                            ("authorization judge (Haiku)", "auth_haiku", "llmauth"),
                            ("authorization judge (Sonnet)", "auth_sonnet", "llmauth")):
        b = JD[key]["benign|real|all"]
        a = JD[key]["attack|all|all"]
        p, lo, hi = wilson(b["k"], b["n"])
        rows.append((label, fam, p, lo, hi, str(b["n"]), a["k"], a["n"], "judge", ""))
    for label, key in (("structural, Haiku parser", "haiku|planner:sonnet|typed"),
                       ("structural, Sonnet parser", "sonnet|planner:sonnet|typed"),
                       ("structural, both parsers", "both|planner:sonnet|typed")):
        r = E[key]
        b = r["benign_blocked|all"]
        cl = r["benign_blocked_cluster"]
        ak = r["sim_attack_allowed|all"]["k"] + r["real_attack_allowed|all"]["k"] + r["r2_real_attack_allowed|all"]["k"]
        an = r["sim_attack_allowed|all"]["n"] + r["real_attack_allowed|all"]["n"] + r["r2_real_attack_allowed|all"]["n"]
        lo, hi = cl["lo"], cl["hi"]
        if b["k"] == 0:  # cluster bootstrap is degenerate at zero events: use the Wilson upper bound
            lo, hi = 0.0, wilson(0, b["n"])[2]
        ex = r["sim_attack_allowed|gateaware:exfil_nonpriv"]["k"]
        other = ak - ex
        note = f"{ex} exfil." + (f" + {other} hijack" if other else "")
        rows.append((label, "struct", b["p"], lo, hi, "1,160", ak, an, "e2e", note))
    col = {"heur": BLUE, "llmdet": ORANGE, "llmauth": YELLOW, "struct": AQUA}
    mk = {"heur": "o", "llmdet": "D", "llmauth": "s", "struct": "^"}
    name = {"heur": "Heuristic text detection / prose matching", "llmdet": "LLM detection judges (Sonnet)",
            "llmauth": "LLM authorization judge", "struct": "Structural gate on parsed actions (typed)"}
    fig = plt.figure(figsize=(8.6, 6.0))
    a1 = fig.add_axes([0.275, 0.20, 0.255, 0.72])
    a2 = fig.add_axes([0.725, 0.20, 0.19, 0.72], sharey=a1)
    plt.setp(a2.get_yticklabels(), visible=False)
    y = np.arange(len(rows))[::-1]
    for yi, r in zip(y, rows):
        label, fam, p, lo, hi, nb, ak, an, aset, note = r
        a1.plot([100 * lo, 100 * hi], [yi, yi], color=col[fam], lw=2.2, solid_capstyle="round", alpha=0.55)
        a1.scatter([100 * p], [yi], s=40, c=col[fam], marker=mk[fam], edgecolors=SURFACE, lw=0.8, zorder=3)
        a1.text(104, yi, f"{100*p:.1f}% [{100*lo:.1f}, {100*hi:.1f}]", va="center", fontsize=10, color=INK2, clip_on=False)
        pa, la, ha = wilson(ak, an)
        a2.plot([100 * la, 100 * ha], [yi, yi], color=col[fam], lw=2.2, solid_capstyle="round", alpha=0.55)
        a2.scatter([100 * pa], [yi], s=40, c=col[fam], marker=mk[fam], edgecolors=SURFACE, lw=0.8, zorder=3)
        a2.text(104, yi, f"{ak}/{an}", va="center", fontsize=10, color=INK2, clip_on=False)
    a1.set_yticks(y, [r[0] for r in rows])
    for ax in (a1, a2):
        ax.grid(True, axis="x", color=GRID, lw=0.6)
        ax.set_xlim(-5, 100)
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_ylim(-0.7, len(rows) - 0.3)
    a1.set_xlabel("Real benign traffic blocked (%)")
    a2.set_xlabel("Attacks allowed (%)")
    a1.set_title("Cost on legitimate traffic", loc="left")
    a2.set_title("Attacks let through", loc="left")
    handles = [plt.Line2D([], [], color=col[f], marker=mk[f], ls="", markersize=7, label=name[f]) for f in col]
    fig.legend(handles=handles, loc="lower center", ncol=2, fontsize=10.5, bbox_to_anchor=(0.5, 0.0))
    fig.savefig(FIG / "fig9_checks.png", dpi=220, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def fig_runs():
    A = json.loads((ROOT / "results" / "v03_analysis.json").read_text())["model_side"]["compliant_runs"]
    R2 = json.loads((ROOT / "results" / "r2_analysis.json").read_text())["model_side"]
    groups = [("Claude Haiku · cued batches", BLUE, "o", [r for r in A if r["model"] == "haiku" and r["attacks"]]),
              ("Claude Sonnet · cued batches + reps", ORANGE, "D", [r for r in A if r["model"] == "sonnet" and r["attacks"]])]
    for key, lab, c, m in (("haiku_mixed_repA", "Claude Haiku · de-cued mixed", BLUE, "o"),
                           ("sonnet_mixed_repA", "Claude Sonnet · de-cued mixed, rep. 1", ORANGE, "D"),
                           ("sonnet_mixed_repB", "Claude Sonnet · de-cued mixed, rep. 2", ORANGE, "D"),
                           ("opus_mixed_repA", "Claude Opus · de-cued mixed", AQUA, "s")):
        groups.append((lab, c, m, R2[key]["per_run"]))
    ocp = ROOT / "results" / "opencode_summary.json"
    if ocp.exists():
        OCS = json.loads(ocp.read_text())
        for mk, lab in (("gpt-6-luna-high", "GPT-6 Luna · mixed, 3 reps"), ("kimi-k3", "Kimi K3 · mixed, 1 rep"),
                        ("glm-5.3-flash", "GLM-5.3 Flash · mixed, 3 reps"),
                        ("deepseek-v4.1-flash", "DeepSeek V4.1 Flash · mixed, 3 reps"),
                        ("minimax-m3.1-flash", "MiniMax M3.1 Flash · mixed, 3 reps")):
            rr = [r for c in ("mixed_rep1", "mixed_rep2", "mixed_rep3") for r in OCS[mk]["orchestrator"].get(c, {}).get("per_run", [])]
            groups.append((lab, GRAY, "^", rr))
    fig, ax = plt.subplots(figsize=(8.6, 0.48 * len(groups) + 1.4))
    ax.grid(True, axis="x", color=GRID, lw=0.6)
    for yi, (lab, c, m, rr) in enumerate(groups[::-1]):
        xs = [100 * r["attempts"] / r["attacks"] for r in rr]
        for x in sorted(set(xs)):
            cnt = xs.count(x)
            ax.scatter([x], [yi], s=34 + 9 * cnt, c=c, marker=m, edgecolors=SURFACE, lw=0.8, zorder=3)
            ax.text(x + (4 if x < 50 else -4), yi + 0.28, f"{cnt} run{'s' if cnt > 1 else ''}",
                    ha="left" if x < 50 else "right", fontsize=8.8, color=INK2)
        k = sum(x > 50 for x in xs)
        ax.text(110, yi, f"{k}/{len(xs)} runs comply", va="center", fontsize=9.5)
    ax.set_yticks(range(len(groups)), [g[0] for g in groups[::-1]])
    ax.set_xlim(-6, 148)
    ax.set_ylim(-0.6, len(groups) - 0.3)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Injected actions carried in one run (% of the run's attack cases)")
    fig.suptitle("Misconfigured policy: injected actions carried per run", x=0.02, ha="left", fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(FIG / "fig8_compliance_runs.png", dpi=220)
    plt.close(fig)


if __name__ == "__main__":
    fig_checks()
    fig_runs()
    print("v0.4 figures written")
