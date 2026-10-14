"""Publication figures for the paper (vector PDF, sized for an ACM single column).

    python paper/figures.py      # reads bench/results/*.csv, writes paper/figures/*.pdf
"""

import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT.parent / "bench" / "results"
OUT = ROOT / "figures"
COLUMN = 3.33  # inches: ACM sigconf column width

plt.rcParams.update(
    {
        # Typeset figure text with LaTeX and the paper's own fonts (Type 1, embeds cleanly).
        "text.usetex": True,
        "text.latex.preamble": r"\usepackage{libertine}\usepackage[libertine]{newtxmath}",
        "font.family": "serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "legend.fontsize": 7,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.6,
        "lines.linewidth": 1.2,
    }
)
BLUE, GREY, ORANGE, GREEN = "#1f5fbf", "#8a8a8a", "#c76a00", "#2e8b57"


def read(name):
    with open(RESULTS / name) as f:
        return list(csv.DictReader(f))


def time_to_block():
    rows = read("time_to_block.csv")
    styles = {
        "expiry": ("Flow expiry (v1)", ORANGE, "-."),
        "early": ("NFStream plugin", GREEN, "--"),
        "fastpath": ("Fast path", BLUE, "-"),
    }
    fig, ax = plt.subplots(figsize=(COLUMN, 2.2))
    for mode, (label, color, ls) in styles.items():
        sub = [r for r in rows if r["mode"] == mode]
        n = len(sub)
        values = sorted(float(r["time_to_block_ms"]) for r in sub if r["time_to_block_ms"])
        # CDF over all trials: never-enforced trials keep the curve below 1.
        ys = [(i + 1) / n for i in range(len(values))]
        xs, ys2 = [values[0]], [0.0]
        for x, y in zip(values, ys, strict=True):
            xs += [x, x]
            ys2 += [ys2[-1], y]
        stopped = sum(r["first_connection"] == "blocked" for r in sub)
        label = f"{label} ({stopped}/{n} first connections stopped)"
        ax.plot(xs, ys2, color=color, ls=ls, label=label)
    ax.set_xscale("log")
    ax.set_xlim(0.4, 2e4)
    ax.set_ylim(0, 1.02)
    ax.set_xticks([1, 10, 100, 1000, 10000], ["1\\,ms", "10\\,ms", "100\\,ms", "1\\,s", "10\\,s"])
    ax.set_xlabel("Time from ClientHello to kernel block")
    ax.set_ylabel("CDF of trials")
    ax.grid(True, which="major", lw=0.3, alpha=0.5)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False, ncol=1,
              borderaxespad=0.2, handlelength=2.2)
    fig.tight_layout(pad=0.2)
    fig.savefig(OUT / "time_to_block.pdf")


def scaling():
    rows = read("drop_cost.csv")
    e3 = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["experiment"] == "E3-scale" and r["filter"] != "none":
            e3[r["filter"]][int(r["blocklist"])].append(int(r["pps"]) / 1e3)
    baseline = statistics.mean(
        int(r["pps"]) / 1e3
        for r in rows
        if r["experiment"] == "E3-scale" and r["filter"] == "none"
    )
    fig, ax = plt.subplots(figsize=(COLUMN, 1.8))
    for kind, label, color, marker in (
        ("xdp", "XDP hash map", BLUE, "o"),
        ("nft", "nftables set", GREEN, "s"),
        ("iptables", "iptables rules", ORANGE, "^"),
    ):
        sizes = sorted(e3[kind])
        means = [statistics.mean(e3[kind][s]) for s in sizes]
        errs = [statistics.stdev(e3[kind][s]) for s in sizes]
        ax.errorbar(sizes, means, yerr=errs, marker=marker, ms=3, capsize=2, lw=1, color=color,
                    label=label)
    ax.axhline(baseline, color=GREY, ls=":", lw=0.9, label="no filter")
    ax.set_xscale("log")
    ax.set_ylim(0, 560)
    ax.set_xticks([1, 10, 100, 1000, 10000], ["1", "10", "100", "1k", "10k"])
    ax.set_xlabel("Addresses in the blocklist")
    ax.set_ylabel("Allowed traffic (kpps)")
    ax.grid(True, which="major", lw=0.3, alpha=0.5)
    ax.legend(loc="lower left", frameon=False, ncol=1, borderaxespad=0.3)
    fig.tight_layout(pad=0.2)
    fig.savefig(OUT / "scaling.pdf")


def drop_table():
    """Q2 is reported as a LaTeX table (four numbers do not need a figure)."""
    rows = [r for r in read("drop_cost.csv") if r["experiment"] == "E2-drop"]
    groups = defaultdict(list)
    for r in rows:
        groups[r["filter"]].append(int(r["pps"]) / 1e3)
    names = {"xdp": "XDP drop (native)", "nft": "nftables \\texttt{netdev} ingress drop",
             "iptables": "iptables \\texttt{INPUT} drop", "none": "No filter (delivered to socket)"}
    lines = []
    for kind in ("xdp", "nft", "iptables", "none"):
        v = groups[kind]
        lines.append(f"{names[kind]} & {statistics.mean(v):.0f} & {statistics.stdev(v):.0f} \\\\")
    (OUT / "drop_table.tex").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    time_to_block()
    scaling()
    drop_table()
    print("wrote", sorted(p.name for p in OUT.iterdir()))
