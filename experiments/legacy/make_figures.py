"""Paper figures (static PNG, light surface) from results/pooled.json + deep.json.

Palette: the validated reference categorical order (blue, orange, aqua, yellow)
plus neutral gray for baselines. Identity is never color-alone: markers differ
and key points are direct-labelled.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIG = ROOT / "paper" / "figures" / "legacy"  # superseded figures of v0.1-v0.3
FIG.mkdir(parents=True, exist_ok=True)

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
GRAY = "#8a8984"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 9.5, "axes.titlesize": 11, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "legend.frameon": False,
})

pooled = json.loads((ROOT / "results" / "pooled.json").read_text())
deep = json.loads((ROOT / "results" / "deep.json").read_text())


def cost(p, cls="pivot"):
    return max(p[cls]["sim_fpr"][0], p[cls]["llm_cost"][0])


# --------------------------------------------------------------------------
# Fig 1: safety / utility frontier (pivot class)
# --------------------------------------------------------------------------
def fig_frontier():
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    groups = {
        "Detection gates (lexical / argument / anchor / composites)": ([], BLUE, "o"),
        "Capability authorization (ours)": ([], ORANGE, "D"),
        "Baselines (no gate / block all)": ([], GRAY, "s"),
    }
    for g, p in pooled.items():
        fam = p["params"].get("family", "")
        if fam in ("lexical_oracle", "argument_oracle", "capability_ablation"):
            continue
        x, y = cost(p) * 100, p["pivot"]["asr"][0] * 100
        if fam.startswith("capability"):
            groups["Capability authorization (ours)"][0].append((x, y, g))
        elif fam in ("none", "strict"):
            groups["Baselines (no gate / block all)"][0].append((x, y, g))
        else:
            groups["Detection gates (lexical / argument / anchor / composites)"][0].append((x, y, g))
    for label, (pts, col, mk) in groups.items():
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        ax.scatter(xs, ys, s=34 if mk != "o" else 18, c=col, marker=mk, label=label,
                   edgecolors=SURFACE, linewidths=0.8, alpha=0.95 if mk != "o" else 0.7, zorder=3)
    # detection-gate frontier
    det = sorted(groups["Detection gates (lexical / argument / anchor / composites)"][0])
    fr = []
    for x, y, g in sorted(det, key=lambda t: (t[0], t[1])):
        if not fr or y < fr[-1][1]:
            fr.append((x, y, g))
    ax.plot([f[0] for f in fr], [f[1] for f in fr], color=BLUE, lw=1.4, alpha=0.9, zorder=2,
            drawstyle="steps-post")
    ann = {
        "taint_gate_v0.1": ("v0.1 lexical gate", (8, 6)),
        "anchor(t=0.30,dir=0)": ("anchor t=0.3", (8, 4)),
        "argument(k=1)": ("argument taint", (8, 4)),
        "lexical(n=2,k=1,dir=1,canon=1)": ("lexical n=2", (-70, 6)),
        "capability(5)": ("capability gate: 0% ASR, 0% cost", (4, 48)),
        "capability(coarse)": ("coarse manifest", (16, 12)),
        "none": ("no gate", (8, -12)),
        "strict_boundary": ("block all", (-52, 8)),
    }
    for g, (txt, off) in ann.items():
        p = pooled[g]
        ax.annotate(txt, (cost(p) * 100, p["pivot"]["asr"][0] * 100), xytext=off,
                    textcoords="offset points", fontsize=8.5, color=INK,
                    arrowprops=dict(arrowstyle="-", color=INK2, lw=0.6))
    ax.set_xlabel("Cost: worst of simulated FPR and real-LLM traffic blocked (%)")
    ax.set_ylabel("Attack success rate, susceptible orchestrators (%)")
    ax.set_title("No detection gate escapes the safety/utility trade-off", loc="left")
    ax.set_xlim(-4, 104)
    ax.set_ylim(-4, 104)
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "fig1_frontier.png", dpi=220)
    plt.close(fig)


# --------------------------------------------------------------------------
# Fig 2: cost on real LLM traffic (pivot class) with Wilson CIs
# --------------------------------------------------------------------------
def fig_llm_cost():
    gates = [("taint_gate_v0.1", "v0.1 lexical (n=4)"),
             ("lexical(n=3,k=1,dir=1,canon=1)", "lexical n=3, canon"),
             ("lexical(n=2,k=1,dir=1,canon=1)", "lexical n=2, canon"),
             ("argument(k=1)", "argument taint"),
             ("anchor(t=0.30,dir=0)", "anchor t=0.3"),
             ("any[L3c+Arg+A0.3]", "lexical+argument+anchor"),
             ("capability(coarse)", "capability (coarse manifest)"),
             ("capability(5)", "capability (action manifest)")]
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    y = np.arange(len(gates))
    h = 0.36
    for j, (key, col, lab) in enumerate([("llm_benign_block", BLUE, "Legitimate delegations blocked"),
                                         ("llm_collateral", ORANGE, "Legitimate lookups on attack pages blocked")]):
        vals = np.array([pooled[g]["pivot"][key][0] * 100 for g, _ in gates])
        lo = np.array([pooled[g]["pivot"][key][1] * 100 for g, _ in gates])
        hi = np.array([pooled[g]["pivot"][key][2] * 100 for g, _ in gates])
        yy = y + (j - 0.5) * h
        ax.barh(yy, vals, height=h * 0.9, color=col, label=lab, zorder=3)
        ax.errorbar(vals, yy, xerr=[vals - lo, hi - vals], fmt="none", ecolor=INK2, elinewidth=0.8,
                    capsize=2, zorder=4)
        for v, h_, yv in zip(vals, hi, yy):
            ax.text(h_ + 1.5, yv, f"{v:.0f}%", va="center", fontsize=7.5, color=INK2)
    ax.set_yticks(y)
    ax.set_yticklabels([l for _, l in gates])
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("Share of real Claude-model traffic blocked (%), 95% Wilson CI")
    ax.set_title("Detection gates block legitimate model traffic", loc="left")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "fig2_llm_cost.png", dpi=220)
    plt.close(fig)


# --------------------------------------------------------------------------
# Fig 3: ASR heatmap — gate x orchestrator restatement behaviour
# --------------------------------------------------------------------------
def fig_behavior_heatmap():
    bd = deep["breakdowns"]
    rows = [("none", "no gate"), ("taint_gate_v0.1", "v0.1 lexical"),
            ("lexical(n=3,k=1,dir=1,canon=1)", "lexical n=3, canon"), ("argument(k=1)", "argument taint"),
            ("anchor(t=0.30,dir=0)", "anchor t=0.3"), ("capability(5)", "capability"),
            ("capability(5)+args(k=2)", "capability + args (k=2)")]
    cols = ["verbatim", "paraphrase", "compress", "mixer", "aligned", "unaligned", "all"]
    keys = ["pivot.behavior=verbatim", "pivot.behavior=paraphrase", "pivot.behavior=compress",
            "pivot.behavior=mixer", "pivot.alignment=aligned", "pivot.alignment=unaligned", "hijack.all"]
    M = np.array([[bd[g][k]["p"] * 100 for k in keys] for g, _ in rows])
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("seq", ["#f0efec", "#9ec5f4", "#3987e5", "#1c5cab", "#0d366b"])
    fig, ax = plt.subplots(figsize=(6.8, 4.1))
    ax.imshow(M, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v = M[i, j]
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8.5,
                    color="#ffffff" if v > 55 else INK)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([l for _, l in rows])
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols)
    for xv in (3.5, 5.5):
        ax.axvline(xv, color=SURFACE, lw=4)
    ax.grid(False)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    # group labels BELOW the tick labels, so they never touch the title
    for xc, txt in ((1.5, "pivots: orchestrator behaviour"), (4.5, "pivots: alignment"),
                    (6.0, "argument\nhijacks")):
        ax.text(xc, M.shape[0] - 0.5 + 0.95, txt, ha="center", va="top", fontsize=8, color=INK2)
    ax.set_title("Attack success (%) by threat class, restatement and alignment", loc="left", pad=10)
    fig.tight_layout()
    fig.savefig(FIG / "fig3_behavior_heatmap.png", dpi=220)
    plt.close(fig)


# --------------------------------------------------------------------------
# Fig 4: manifest coverage ablation
# --------------------------------------------------------------------------
def fig_coverage():
    cur = deep["coverage"]["curve"]
    xs = sorted(int(k) for k in cur)
    mean = [cur[str(x)]["mean"] * 100 if str(x) in cur else cur[x]["mean"] * 100 for x in xs]
    lo = [cur[str(x)]["min"] * 100 if str(x) in cur else cur[x]["min"] * 100 for x in xs]
    hi = [cur[str(x)]["max"] * 100 if str(x) in cur else cur[x]["max"] * 100 for x in xs]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    ax.fill_between(xs, lo, hi, color=ORANGE, alpha=0.15, lw=0)
    ax.plot(xs, mean, color=ORANGE, lw=2, marker="o", ms=6, mec=SURFACE, mew=1)
    for x, m in zip(xs, mean):
        ax.text(x, m + 5, f"{m:.0f}%", ha="center", fontsize=8, color=INK2)
    ax.set_xticks(xs)
    ax.set_xlabel("Privileged capabilities covered by the manifest (of 5)")
    ax.set_ylabel("Pivot ASR, susceptible orchestrators (%)")
    ax.set_ylim(-5, 112)
    ax.set_title("Capability gating is only as good as its manifest", loc="left")
    ax.text(0.2, 8, "band = min–max over all\nmanifest subsets of that size", fontsize=7.5, color=INK2)
    fig.tight_layout()
    fig.savefig(FIG / "fig4_coverage.png", dpi=220)
    plt.close(fig)


# --------------------------------------------------------------------------
# Fig 5: latency vs payload length
# --------------------------------------------------------------------------
def fig_latency():
    lat = deep["latency"]
    Ls = sorted(int(k) for k in lat)
    series = [("taint_gate_v0.1", "v0.1 lexical", BLUE), ("argument(k=1)", "argument taint", ORANGE),
              ("anchor(t=0.3)", "anchor", AQUA), ("capability(5)+args", "capability + args", YELLOW)]
    fig, ax = plt.subplots(figsize=(5.4, 3.5))
    for key, lab, col in series:
        ys = [lat[str(L)][key]["median_ms"] for L in Ls]
        ax.plot(Ls, ys, color=col, lw=2, marker="o", ms=5, mec=SURFACE, mew=1, label=lab)
        ax.text(Ls[-1] * 1.25, ys[-1], lab, va="center", fontsize=8, color=INK)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(70, 900000)
    ax.set_xlabel("Payload and untrusted-span length (characters)")
    ax.set_ylabel("Median gate latency (ms)")
    ax.set_title("All gates are sub-millisecond at realistic sizes", loc="left")
    ax.axvspan(70, 2000, color=GRID, alpha=0.5, lw=0)
    ax.text(110, ax.get_ylim()[1] * 0.5, "typical\npayloads", fontsize=7.5, color=INK2)
    ax.legend(loc="upper left", fontsize=7.5, bbox_to_anchor=(0.18, 1.0))
    fig.tight_layout()
    fig.savefig(FIG / "fig5_latency.png", dpi=220)
    plt.close(fig)


if __name__ == "__main__":
    fig_frontier()
    fig_llm_cost()
    fig_behavior_heatmap()
    fig_coverage()
    fig_latency()
    print("figures:", sorted(p.name for p in FIG.glob("*.png")))
