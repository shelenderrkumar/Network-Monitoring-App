"""Publication figures for the paper (vector PDF, sized for an ACM single column).

python paper/figures.py      # reads bench/results/*.csv, writes paper/figures/*.pdf
"""

import csv
import math
import random
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


def wilson(k, n, z=1.96):
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def median_ci(values, reps=10000, seed=1):
    """Median with a 95% percentile-bootstrap confidence interval."""
    rng = random.Random(seed)
    meds = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(reps))
    return statistics.median(values), meds[int(0.025 * reps)], meds[int(0.975 * reps)]


def ttb(rows):
    return [float(r["time_to_block_ms"]) for r in rows if r["time_to_block_ms"]]


def stopped(rows):
    return sum(r["first_connection"] == "blocked" for r in rows)


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
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        frameon=False,
        ncol=1,
        borderaxespad=0.2,
        handlelength=2.2,
    )
    fig.tight_layout(pad=0.2)
    fig.savefig(OUT / "time_to_block.pdf")


def rtt_sweep():
    """Fraction of first connections stopped against the emulated RTT, with 95% CIs.

    The dashed line predicts the plugin's curve from its delay-0 time-to-block
    distribution alone: a connection is stopped when the block lands before the reply.
    """
    rows = read("rtt_sweep.csv") + [
        r for r in read("time_to_block.csv") if r["mode"] in ("early", "fastpath")
    ]
    for r in rows:
        r.setdefault("delay_ms", "0")
    delays = sorted({int(r["delay_ms"]) for r in rows})
    xs = range(len(delays))
    fig, ax = plt.subplots(figsize=(COLUMN, 1.9))
    for mode, label, color, marker in (
        ("fastpath", "Fast path", BLUE, "o"),
        ("early", "NFStream plugin", GREEN, "s"),
    ):
        ps, lo, hi = [], [], []
        for d in delays:
            sub = [r for r in rows if r["mode"] == mode and int(r["delay_ms"]) == d]
            k, n = stopped(sub), len(sub)
            a, b = wilson(k, n)
            ps.append(k / n)
            lo.append(k / n - a)
            hi.append(b - k / n)
        ax.errorbar(
            xs, ps, yerr=[lo, hi], marker=marker, ms=3, capsize=2, lw=1, color=color, label=label
        )
    base = ttb([r for r in read("time_to_block.csv") if r["mode"] == "early"])
    pred = [sum(t < d for t in base) / len(base) for d in delays]
    ax.plot(xs, pred, color=GREEN, ls=":", lw=1, label="plugin, predicted from delay 0")
    ax.set_xticks(list(xs), [str(d) for d in delays])
    ax.set_ylim(-0.03, 1.05)
    ax.set_xlabel("Emulated round-trip time to the server (ms)")
    ax.set_ylabel("First connections stopped")
    ax.grid(True, which="major", lw=0.3, alpha=0.5)
    ax.legend(loc="center right", frameon=False, borderaxespad=0.3)
    fig.tight_layout(pad=0.2)
    fig.savefig(OUT / "rtt_sweep.pdf")


def split_table():
    """Time-to-block when the server name arrives in the ClientHello's second segment."""
    rows = read("split_hello.csv")
    names = {
        "fastpath": "Fast path, plugin fallback (v2)",
        "fastpath:expiry": "Fast path, flow-export fallback",
    }
    lines = []
    for mode in ("fastpath", "fastpath:expiry"):
        for d in sorted({int(r["delay_ms"]) for r in rows}):
            sub = [r for r in rows if r["mode"] == mode and int(r["delay_ms"]) == d]
            med, lo, hi = median_ci(ttb(sub))
            fmt = (lambda v: f"{v / 1000:.1f}\,s") if med >= 1000 else (lambda v: f"{v:.0f}\,ms")
            lines.append(
                f"{names[mode]} & {d} & {fmt(med)} [{fmt(lo)}, {fmt(hi)}] & "
                f"{stopped(sub)}/{len(sub)} \\\\"
            )
    (OUT / "split_table.tex").write_text("\n".join(lines) + "\n")


def numbers():
    """LaTeX macros for every number quoted in the text, computed from the raw CSVs."""
    rows = read("time_to_block.csv")
    out = []

    def macro(name, value):
        out.append(f"\\newcommand{{\\{name}}}{{{value}}}")

    for mode, key in (("expiry", "Exp"), ("early", "Early"), ("fastpath", "Fast")):
        sub = [r for r in rows if r["mode"] == mode]
        t = ttb(sub)
        med, lo, hi = median_ci(t)
        nd = 1 if med < 10 else 0
        macro(f"n{key}", len(sub))
        macro(f"enforced{key}", len(t))
        macro(f"stopped{key}", stopped(sub))
        macro(f"controls{key}", sum(r["control_connection"] == "completed" for r in sub))
        macro(f"med{key}", f"{med:.{nd + (1 if med < 1 else 0)}f}")
        macro(f"lo{key}", f"{lo:.{nd + (1 if lo < 1 else 0)}f}")
        macro(f"hi{key}", f"{hi:.{nd + (1 if hi < 1 else 0)}f}")
        macro(f"min{key}", f"{min(t):.{2 if min(t) < 10 else 0}f}")
        macro(f"max{key}", f"{max(t):.{2 if max(t) < 10 else 0}f}")
    fast = [r for r in rows if r["mode"] == "fastpath"]
    d2e = [float(r["detect_to_enforce_ms"]) for r in fast if r["detect_to_enforce_ms"]]
    macro("medFastDetect", f"{statistics.median(d2e):.2f}")
    macro("controlsAll", sum(r["control_connection"] == "completed" for r in rows))
    macro("trialsAll", len(rows))
    sweep = read("rtt_sweep.csv")
    words = {5: "five", 10: "ten", 25: "twentyfive", 50: "fifty", 100: "hundred",
             250: "twofifty", 500: "fivehundred", 1000: "thousand"}  # fmt: skip
    for mode, key in (("early", "Early"), ("fastpath", "Fast")):
        for d, word in words.items():
            sub = [r for r in sweep if r["mode"] == mode and int(r["delay_ms"]) == d]
            macro(f"sweep{key}{word}", stopped(sub))
    macro("sweepN", sum(1 for r in sweep if r["mode"] == "early" and r["delay_ms"] == "5"))
    macro("sweepControls", sum(r["control_connection"] == "completed" for r in sweep))
    macro("sweepTrials", len(sweep))
    split = read("split_hello.csv")
    macro("splitControls", sum(r["control_connection"] == "completed" for r in split))
    macro("splitTrials", len(split))
    (OUT / "numbers.tex").write_text("\n".join(out) + "\n")


def scaling():
    rows = read("drop_cost.csv")
    e3 = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["experiment"] == "E3-scale" and r["filter"] != "none":
            e3[r["filter"]][int(r["blocklist"])].append(int(r["pps"]) / 1e3)
    baseline = statistics.mean(
        int(r["pps"]) / 1e3 for r in rows if r["experiment"] == "E3-scale" and r["filter"] == "none"
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
        ax.errorbar(
            sizes, means, yerr=errs, marker=marker, ms=3, capsize=2, lw=1, color=color, label=label
        )
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
    names = {
        "xdp": "XDP drop (native)",
        "nft": "nftables \\texttt{netdev} ingress drop",
        "iptables": "iptables \\texttt{INPUT} drop",
        "none": "No filter (delivered to socket)",
    }
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
    numbers()
    rtt_sweep()
    split_table()
    print("wrote", sorted(p.name for p in OUT.iterdir()))
