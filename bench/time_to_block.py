"""E1: time-to-block and first-connection outcome for each decision mode.

For every trial the client (host side) opens a TLS connection to its own server address
10.0.1.<i> in namespace ``gen`` with SNI ``t<i>.blocked.test``, so earlier trials never
pre-block later ones. The client records the wall-clock time just before it sends the
ClientHello; DPI Guard records when it wrote the IP to the XDP map. Their difference is
the time-to-block. We also record whether the handshake and one HTTP exchange completed.

Control trials to ``c<i>.allowed.test`` on 10.0.2.<i> must always complete.

Usage (root, after testbed.sh):  python bench/time_to_block.py --trials 30
"""

import argparse
import csv
import json
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NS = "gen"

CLIENT = r"""
import json, socket, ssl, sys, time
ip, name = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection((ip, 443), timeout=2)
t_hello = time.time()
try:
    tls = ctx.wrap_socket(raw, server_hostname=name)
    tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    ok = tls.recv(100).startswith(b"HTTP/1.1 200")
    tls.close()
    outcome = "completed" if ok else "broken"
except (OSError, ssl.SSLError) as exc:
    outcome = "blocked"
print(json.dumps({"t_hello": t_hello, "outcome": outcome, "elapsed": time.time() - t_hello}))
"""


def sh(*cmd, check=True):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def prepare_addresses(n):
    for i in range(1, n + 1):
        for net in ("10.0.1", "10.0.2"):
            sh(
                "ip",
                "netns",
                "exec",
                NS,
                "ip",
                "addr",
                "add",
                f"{net}.{i}/32",
                "dev",
                "veth1",
                check=False,
            )
    for net in ("10.0.1.0/24", "10.0.2.0/24"):
        sh("ip", "route", "replace", net, "via", "10.0.0.2", "dev", "veth0")


def client(ip, name):
    out = sh(sys.executable, "-c", CLIENT, ip, name)
    return json.loads(out.stdout)


def state(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state") as r:
        return json.load(r)


def run_mode(mode, trials, idle_timeout, port):
    app = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dpiguard.cli",
            "--iface",
            "veth0",
            "--mode",
            mode,
            "--block",
            "blocked.test",
            "--idle-timeout",
            str(idle_timeout),
            "--port",
            str(port),
        ],
        cwd=ROOT.parent,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz")
                break
            except OSError:
                time.sleep(0.1)
        time.sleep(3)  # let NFStream start capturing
        results = []
        for i in range(1, trials + 1):
            blocked = client(f"10.0.1.{i}", f"t{i}.blocked.test")
            control = client(f"10.0.2.{i}", f"c{i}.allowed.test")
            results.append((i, blocked, control))
            time.sleep(0.25)
        time.sleep(idle_timeout + 4)  # let expiry-mode decisions land
        events = {e["ip"]: e for e in state(port)["events"]}
    finally:
        app.terminate()
        app.wait()
    rows = []
    for i, blocked, control in results:
        event = events.get(f"10.0.1.{i}")
        rows.append(
            {
                "mode": mode,
                "trial": i,
                "first_connection": blocked["outcome"],
                "control_connection": control["outcome"],
                "time_to_block_ms": round(1000 * (event["enforced_at"] - blocked["t_hello"]), 3)
                if event
                else "",
                "detect_to_enforce_ms": round(
                    1000 * (event["enforced_at"] - event["detected_at"]), 3
                )
                if event
                else "",
                "enforced_by": event["mode"] if event else "",
            }
        )
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--idle-timeout", type=int, default=5)
    parser.add_argument("--modes", default="expiry,early,fastpath")
    args = parser.parse_args()
    prepare_addresses(args.trials)
    rows = []
    for n, mode in enumerate(args.modes.split(",")):
        rows += run_mode(mode, args.trials, args.idle_timeout, 5100 + n)
        print(f"{mode}: done", flush=True)
    out = ROOT / "results" / "time_to_block.csv"
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for mode in args.modes.split(","):
        sub = [r for r in rows if r["mode"] == mode]
        ttb = sorted(r["time_to_block_ms"] for r in sub if r["time_to_block_ms"] != "")
        stopped = sum(r["first_connection"] == "blocked" for r in sub)
        controls = sum(r["control_connection"] == "completed" for r in sub)
        if ttb:
            print(
                f"{mode:9} n={len(sub)} enforced={len(ttb)} "
                f"median TTB={statistics.median(ttb):8.1f} ms "
                f"p90={ttb[int(0.9 * (len(ttb) - 1))]:8.1f} ms "
                f"first conn blocked={stopped}/{len(sub)} controls ok={controls}/{len(sub)}"
            )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
