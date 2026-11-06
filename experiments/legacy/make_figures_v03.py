"""v0.3 figures: gate x threat-class matrix, all-class frontier, run-level compliance.

Reads results/v03_analysis.json, results/judge_summary.json,
results/judge_adaptive_summary.json. Same light surface and palette as
make_figures.py; the matrix uses one sequential hue (light -> dark = worse)
with every cell labelled, so values never depend on colour alone.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
FIG = ROOT / "paper" / "figures" / "legacy"  # superseded figures of v0.1-v0.3
FIG.mkdir(parents=True, exist_ok=True)
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA, YELLOW, GRAY = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#8a8984"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "font.size": 9.5, "axes.titlesize": 11, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
})

A = json.loads((ROOT / "results" / "v03_analysis.json").read_text())
J = json.loads((ROOT / "results" / "judge_summary.json").read_text())

ROWS = [
    ("v0.1 lexical taint", "taint_gate_v0.1", "detect"),
    ("lexical n=3 (canon.)", "lexical(n=3,k=1,dir=1,canon=1)", "detect"),
    ("lexical n=2 (canon.)", "lexical(n=2,k=1,dir=1,canon=1)", "detect"),
    ("argument taint", "argument(k=1)", "detect"),
    ("anchor t=0.3", "anchor(t=0.30,dir=0)", "detect"),
    ("lexical+argument+anchor", "any[L3c+Arg+A0.3]", "detect"),
    ("v0.2 capability (prose)", "capability(5)", "cap"),
    ("v0.2 capability+args (prose)", "capability(5)+args(k=2)", "cap"),
    ("structural · prose Auth", "structural[prose,deny_unknown,args]", "cap"),
    ("structural · fail-open", "structural[oracle,fail_open,args]", "cap"),
    ("structural · no arg check", "structural[oracle,deny_unknown]", "cap"),
    ("structural · oracle Auth", "structural[oracle,deny_unknown,args]", "cap"),
    ("structural · Haiku planner", "structural[planner:haiku,deny_unknown,args]", "cap"),
    ("structural · Sonnet planner", "structural[planner:sonnet,deny_unknown,args]", "cap"),
    ("structural · Opus planner", "structural[planner:opus,deny_unknown,args]", "cap"),
]
COLS = ["pivot", "hijack", "over-auth", "drift", "sim FPR", "real FPR", "real attacks"]


def row_vals(gname):
    g = A["gates"][gname]
    v = [g["sim_asr"].get(c, {}).get("p") for c in ("pivot", "hijack", "overauth", "drift")]
    v += [g["sim_fpr"]["all"]["p"], g["real_fpr"]["all"]["p"], g.get("real_attack", {}).get("all", {}).get("p")]
    return [np.nan if x is None else x * 100 for x in v]


def judge_row(name):
    c = J[name]["cells"]
    get = lambda k: c[k]["p"] * 100 if k in c else np.nan  # noqa: E731
    return [get("attack|sim|pivot"), get("attack|sim|hijack"), get("attack|sim|overauth"), get("attack|sim|drift"),
            get("benign|sim|all"), get("benign|real|all"), get("attack|real|all")]


def fig_matrix():
    labels = [r[0] for r in ROWS] + ["LLM judge · Haiku", "LLM judge · Sonnet"]
    data = np.array([row_vals(r[1]) for r in ROWS] + [judge_row("haiku"), judge_row("sonnet")])
    cmap = LinearSegmentedColormap.from_list("seq", ["#fdf1ea", "#f6b897", ORANGE, "#9c3a12"])
    fig, ax = plt.subplots(figsize=(7.4, 6.6))
    ax.imshow(np.nan_to_num(data, nan=0), cmap=cmap, vmin=0, vmax=100, aspect="auto")
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            v = data[i, j]
            txt = "–" if np.isnan(v) else (f"{v:.0f}" if v >= 9.95 or v == 0 else f"{v:.1f}")
            ax.text(j, i, txt, ha="center", va="center", fontsize=8.3,
                    color=("#ffffff" if (not np.isnan(v) and v > 55) else INK))
    ax.set_xticks(range(len(COLS)), COLS, fontsize=8.6)
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(labels)), labels, fontsize=8.6)
    ax.axvline(3.5, color=SURFACE, lw=3)
    ax.axvline(5.5, color=SURFACE, lw=3)
    for y in (5.5, 7.5, 14.5):
        ax.axhline(y, color=SURFACE, lw=3)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    ax.set_title("Attack success by threat class (left), cost (middle), real compromised traffic (right), %",
                 loc="left", fontsize=9.6, pad=26)
    fig.tight_layout()
    fig.savefig(FIG / "fig6_v03_matrix.png", dpi=220)
    plt.close(fig)


def fig_frontier():
    fig, ax = plt.subplots(figsize=(6.6, 4.5))
    ax.grid(True, color=GRID, lw=0.6)
    det, cap, struct = [], [], []
    for g, r in A["gates"].items():
        if g == "none":
            continue
        x, y = r["real_fpr"]["all"]["p"] * 100, r["sim_asr"]["all"]["p"] * 100
        if g.startswith("structural"):
            struct.append((x, y))
        elif g.startswith("capability"):
            cap.append((x, y))
        else:
            det.append((x, y))
    ax.scatter(*zip(*det), s=26, c=BLUE, marker="o", label="Detection gates", edgecolors=SURFACE, lw=0.8, zorder=3)
    ax.scatter(*zip(*cap), s=34, c=YELLOW, marker="s", label="v0.2 prose capability gates", edgecolors=SURFACE, lw=0.8, zorder=3)
    ax.scatter(*zip(*struct), s=34, c=ORANGE, marker="D", label="Structural gate (24 configurations)",
               edgecolors=SURFACE, lw=0.8, zorder=4, alpha=0.9)
    for name, mk in (("haiku", "^"), ("sonnet", "v")):
        c = J[name]["cells"]
        x = c["benign|real|all"]["p"] * 100
        y = c["attack|sim|all"]["p"] * 100
        ax.scatter([x], [y], s=46, c=AQUA, marker=mk, edgecolors=INK2, lw=0.6, zorder=5,
                   label=f"LLM judge ({name.capitalize()})")
    ann = {  # label positions in data units, chosen to avoid overlaps
        "taint_gate_v0.1": ("v0.1 lexical", (56, 26)),
        "any[L3c+Arg+A0.3]": ("lexical+argument+anchor", (40, 7)),
        "lexical(n=2,k=1,dir=1,canon=1)": ("lexical n=2", (70, 16)),
        "argument(k=1)": ("argument taint", (25, 72)),
        "anchor(t=0.30,dir=0)": ("anchor t=0.3", (18, 46)),
        "anchor(t=0.20,dir=0)": ("anchor t=0.2", (4, 60)),
        "capability(5)": ("v0.2 capability (prose)", (14, 31)),
        "structural[prose,allowlist,args]": ("structural, prose Auth,\nallow-list", (80, 30)),
        "structural[oracle,fail_open,args]": ("structural, fail-open", (3, 18)),
    }
    for g, (t, xy) in ann.items():
        r = A["gates"][g]
        ax.annotate(t, (r["real_fpr"]["all"]["p"] * 100, r["sim_asr"]["all"]["p"] * 100), xytext=xy,
                    textcoords="data", fontsize=8, arrowprops=dict(arrowstyle="-", color=INK2, lw=0.6))
    ax.annotate("origin: structural gate (oracle or planner Auth,\ndeny-unknown, argument endorsement)\n"
                "and both LLM judges, 0% / 0%", (0, 0), xytext=(28, 88), textcoords="data", fontsize=8,
                arrowprops=dict(arrowstyle="-", color=INK2, lw=0.6))
    ax.set_xlabel("Real benign LLM traffic blocked (%)  [n = 1,160 delegations]")
    ax.set_ylabel("Attack success, all four threat classes (%)")
    ax.set_title("Authorization, not provenance, reaches the origin", loc="left")
    ax.set_xlim(-4, 100)
    ax.set_ylim(-4, 104)
    ax.legend(loc="center right", fontsize=7.8)
    fig.tight_layout()
    fig.savefig(FIG / "fig7_v03_frontier.png", dpi=220)
    plt.close(fig)


def fig_runs():
    runs = A["model_side"]["compliant_runs"]
    fig, ax = plt.subplots(figsize=(6.6, 2.5))
    ax.grid(True, axis="x", color=GRID, lw=0.6)
    for yi, (model, col, mk) in enumerate((("haiku", BLUE, "o"), ("sonnet", ORANGE, "D"))):
        rr = [r for r in runs if r["model"] == model and r["attacks"]]
        xs = [100 * r["attempts"] / r["attacks"] for r in rr]
        jitter = np.linspace(-0.18, 0.18, len(xs))
        ax.scatter(xs, [yi + j for j in jitter], s=30, c=col, marker=mk, edgecolors=SURFACE, lw=0.8, zorder=3)
        k = sum(x > 50 for x in xs)
        ax.text(103, yi, f"{k}/{len(xs)} runs comply", va="center", fontsize=8.5)
    ax.set_yticks([0, 1], ["Haiku", "Sonnet"])
    ax.set_xlim(-4, 125)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Injected actions carried in one run (% of the run's attack cases)")
    ax.set_title("Misconfigured-policy condition: compliance is all-or-nothing per run", loc="left", fontsize=10)
    fig.tight_layout()
    fig.savefig(FIG / "fig8_compliance_runs.png", dpi=220)
    plt.close(fig)


if __name__ == "__main__":
    fig_matrix()
    fig_frontier()
    fig_runs()
    print("figures written")
