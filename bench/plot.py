"""Turn bench/results/*.csv into the figures used in the README and the paper."""

import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
OUT = ROOT.parent / "docs" / "figures"
COLORS = {
    "xdp": "#2f6fed",
    "nft": "#16a34a",
    "iptables": "#d97706",
    "none": "#6b7280",
    "expiry": "#d97706",
    "early": "#16a34a",
    "fastpath": "#2f6fed",
}
plt.rcParams.update(
    {"font.size": 10, "axes.spines.top": False, "axes.spines.right": False, "svg.fonttype": "none"}
)


def read(name):
    with open(ROOT / "results" / name) as f:
        return list(csv.DictReader(f))


def _fmt_ms(ms):
    return f"{ms / 1000:.1f} s" if ms >= 1000 else f"{ms:.0f} ms" if ms >= 10 else f"{ms:.1f} ms"


def time_to_block():
    rows = read("time_to_block.csv")
    modes = [m for m in ("expiry", "early", "fastpath") if any(r["mode"] == m for r in rows)]
    names = {"expiry": "flow expiry (v1)", "early": "NFStream plugin", "fastpath": "fast path (v2)"}
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for y, mode in enumerate(modes):
        sub = [r for r in rows if r["mode"] == mode]
        values = [float(r["time_to_block_ms"]) for r in sub if r["time_to_block_ms"]]
        jitter = [y + (i % 7 - 3) * 0.04 for i in range(len(values))]
        ax.scatter(values, jitter, s=14, color=COLORS[mode], alpha=0.75)
        med = statistics.median(values)
        ax.plot([med, med], [y - 0.28, y + 0.28], color="black", lw=1.5)
        ax.annotate(f"median {_fmt_ms(med)}", (med, y + 0.3), ha="center", fontsize=9)
        stopped = sum(r["first_connection"] == "blocked" for r in sub)
        ax.annotate(
            f"{stopped}/{len(sub)}",
            (1.02, y),
            xycoords=("axes fraction", "data"),
            va="center",
            fontsize=10,
            fontweight="bold" if stopped else "normal",
        )
    ax.annotate(
        "first conn.\nstopped",
        (1.02, len(modes) - 0.35),
        xycoords=("axes fraction", "data"),
        fontsize=8,
        color="#6b7280",
    )
    ax.set_xscale("log")
    ax.set_xlim(0.4, 2e4)
    ax.set_xticks([1, 10, 100, 1000, 10000], ["1 ms", "10 ms", "100 ms", "1 s", "10 s"])
    ax.set_yticks(range(len(modes)), [names[m] for m in modes])
    ax.set_ylim(-0.6, len(modes) - 0.1)
    ax.set_xlabel("Time from ClientHello to kernel block (log scale)")
    fig.tight_layout()
    fig.savefig(OUT / "time_to_block.svg")


def drop_cost():
    rows = read("drop_cost.csv")
    e2 = defaultdict(list)
    e3 = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["experiment"] == "E2-drop":
            e2[r["filter"]].append(int(r["pps"]) / 1e3)
        elif r["filter"] != "none":
            e3[r["filter"]][int(r["blocklist"])].append(int(r["pps"]) / 1e3)
    baseline = [
        int(r["pps"]) / 1e3 for r in rows if r["experiment"] == "E3-scale" and r["filter"] == "none"
    ]

    fig, ax = plt.subplots(figsize=(5.2, 2.6))
    order = [k for k in ("none", "xdp", "nft", "iptables") if k in e2]
    means = [statistics.mean(e2[k]) for k in order]
    errs = [statistics.pstdev(e2[k]) for k in order]
    labels = {
        "none": "no filter\n(delivered)",
        "xdp": "XDP drop",
        "nft": "nftables\ningress drop",
        "iptables": "iptables\nINPUT drop",
    }
    ax.bar(
        [labels[k] for k in order], means, yerr=errs, capsize=4, color=[COLORS[k] for k in order]
    )
    ax.set_ylabel("Sender rate (kpps)")
    fig.tight_layout()
    fig.savefig(OUT / "drop_cost.svg")

    fig, ax = plt.subplots(figsize=(5.2, 2.8))
    for kind in ("xdp", "nft", "iptables"):
        sizes = sorted(e3[kind])
        means = [statistics.mean(e3[kind][s]) for s in sizes]
        errs = [statistics.pstdev(e3[kind][s]) for s in sizes]
        name = {"xdp": "XDP hash map", "nft": "nftables set", "iptables": "iptables rules"}[kind]
        ax.errorbar(sizes, means, yerr=errs, marker="o", capsize=3, label=name, color=COLORS[kind])
    if baseline:
        ax.axhline(
            statistics.mean(baseline), color=COLORS["none"], ls="--", lw=1, label="no filter"
        )
    ax.set_xscale("log")
    ax.set_xlabel("Blocked addresses (log scale)")
    ax.set_ylabel("Allowed traffic (kpps)")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "scaling.svg")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    if (ROOT / "results" / "drop_cost.csv").exists():
        drop_cost()
    if (ROOT / "results" / "time_to_block.csv").exists():
        time_to_block()
    print("figures in", OUT)
