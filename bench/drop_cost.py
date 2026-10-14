"""E2 (drop cost) and E3 (blocklist scaling) on a veth testbed.

Testbed (see testbed.sh): the sender runs in network namespace ``gen`` (10.0.0.2) and
floods UDP packets at the host side of the veth pair (``veth0``, 10.0.0.1), where the
filters are installed. On a veth pair the receive path runs on the sending CPU, so the
sender's achieved packet rate is the end-to-end cost of one packet through the stack:
the cheaper the filter's path, the more packets per second one core can push.

E2: the sender's own address is blocked; how fast can each mechanism discard a flood?
E3: the sender is NOT blocked, but N other addresses are; what does every *allowed*
    packet pay for checking a blocklist of size N?

Usage (root):  python bench/drop_cost.py --runs 5 --seconds 5
"""

import argparse
import csv
import ipaddress
import random
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from dpiguard.enforcers import NftEnforcer, XdpEnforcer  # noqa: E402

IFACE, SENDER_IP, HOST_IP, NS = "veth0", "10.0.0.2", "10.0.0.1", "gen"


def cpu_busy() -> tuple[int, int]:
    with open("/proc/stat") as f:
        fields = [int(x) for x in f.readline().split()[1:]]
    idle = fields[3] + fields[4]
    return sum(fields) - idle, sum(fields)


def flood(seconds: float) -> tuple[float, float]:
    """Run the sender; return (packets per second, fraction of all CPUs busy)."""
    busy0, total0 = cpu_busy()
    start = time.perf_counter()
    out = subprocess.run(
        [
            "taskset",
            "-c",
            "1",
            "ip",
            "netns",
            "exec",
            NS,
            str(ROOT / "udpflood"),
            SENDER_IP,
            HOST_IP,
            "9",
            str(seconds),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    elapsed = time.perf_counter() - start
    busy1, total1 = cpu_busy()
    return int(out.stdout) / elapsed, (busy1 - busy0) / max(total1 - total0, 1)


class Iptables:
    name = "iptables"

    def __init__(self):
        subprocess.run(["iptables", "-F", "INPUT"], check=True)

    def load(self, ips):
        rules = "\n".join(f"-A INPUT -s {ip} -j DROP" for ip in ips)
        subprocess.run(
            ["iptables-restore", "--noflush"],
            input=f"*filter\n{rules}\nCOMMIT\n",
            text=True,
            check=True,
        )

    def block(self, ip):
        self.load([ip])

    def close(self):
        subprocess.run(["iptables", "-F", "INPUT"], check=True)


class NoFilter:
    name = "none"

    def block(self, ip):
        pass

    def load(self, ips):
        pass

    def close(self):
        pass


def make(kind):
    return {
        "none": NoFilter,
        "xdp": lambda: XdpEnforcer(IFACE),
        "nft": lambda: NftEnforcer(IFACE),
        "iptables": Iptables,
    }[kind]()


def bulk_load(enforcer, ips):
    if hasattr(enforcer, "load"):
        enforcer.load(ips)
    elif isinstance(enforcer, NftEnforcer):
        for i in range(0, len(ips), 1000):
            chunk = ", ".join(ips[i : i + 1000])
            subprocess.run(
                ["nft", "add", "element", "netdev", "dpiguard", "blocked4", f"{{ {chunk} }}"],
                check=True,
            )
    else:
        for ip in ips:
            enforcer.block(ip)


def random_ips(n, seed=7):
    rng = random.Random(seed)
    net = ipaddress.ip_network("172.16.0.0/12")
    return [str(net[rng.randrange(1, net.num_addresses - 1)]) for _ in range(n)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--sizes", default="1,100,1000,10000")
    args = parser.parse_args()

    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # allowed packets end here
    sink.bind((HOST_IP, 9))

    rows = []
    # E2: drop a flood from the blocked sender
    for kind in ["none", "xdp", "nft", "iptables"]:
        for run in range(args.runs):
            enforcer = make(kind)
            try:
                enforcer.block(SENDER_IP)
                pps, cpu = flood(args.seconds)
            finally:
                enforcer.close()
            rows.append(
                {
                    "experiment": "E2-drop",
                    "filter": kind,
                    "blocklist": 1 if kind != "none" else 0,
                    "run": run,
                    "pps": round(pps),
                    "cpu_busy": round(cpu, 4),
                }
            )
            print(rows[-1], flush=True)

    # E3: allowed traffic while N other addresses are blocked
    sizes = [int(s) for s in args.sizes.split(",")]
    for kind in ["xdp", "nft", "iptables"]:
        for size in sizes:
            for run in range(args.runs):
                enforcer = make(kind)
                try:
                    bulk_load(enforcer, random_ips(size))
                    pps, cpu = flood(args.seconds)
                finally:
                    enforcer.close()
                rows.append(
                    {
                        "experiment": "E3-scale",
                        "filter": kind,
                        "blocklist": size,
                        "run": run,
                        "pps": round(pps),
                        "cpu_busy": round(cpu, 4),
                    }
                )
                print(rows[-1], flush=True)
    for run in range(args.runs):  # reference: no filter at all
        pps, cpu = flood(args.seconds)
        rows.append(
            {
                "experiment": "E3-scale",
                "filter": "none",
                "blocklist": 0,
                "run": run,
                "pps": round(pps),
                "cpu_busy": round(cpu, 4),
            }
        )

    out = ROOT / "results" / "drop_cost.csv"
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {out}")
    for (exp, kind, size), group in _group(rows).items():
        print(
            f"{exp:9} {kind:9} N={size:<6} {statistics.mean(group) / 1e3:8.1f} kpps "
            f"± {statistics.pstdev(group) / 1e3:.1f}"
        )


def _group(rows):
    out = {}
    for r in rows:
        out.setdefault((r["experiment"], r["filter"], r["blocklist"]), []).append(r["pps"])
    return out


if __name__ == "__main__":
    main()
