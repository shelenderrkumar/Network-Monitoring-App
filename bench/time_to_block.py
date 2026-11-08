"""E1: time-to-block and first-connection outcome for each decision mode.

For every trial the client (host side) opens a TLS connection to its own server address
10.0.1.<i> in namespace ``gen`` with SNI ``t<i>.blocked.test``, so earlier trials never
pre-block later ones. The client records the wall-clock time just before it sends the
ClientHello; DPI Guard records when it wrote the IP to the XDP map. Their difference is
the time-to-block. We also record whether the handshake and one HTTP exchange completed.

Control trials to ``c<i>.allowed.test`` on 10.0.2.<i> must always complete.

Options for the follow-up experiments:
  --delays 0,5,25   restart the testbed server with each reply delay (emulated RTT, ms)
  --split N         send the ClientHello as two TCP segments, the first N bytes alone
                    (N=100 puts the server name in the second segment)
  --modes fastpath:expiry   fast path with the old flow-export fallback

Usage (root, after testbed.sh):  python bench/time_to_block.py --trials 100
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
ip, name, split = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection((ip, 443), timeout=2)
raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(inc, out, server_hostname=name)

def step(fn, *a):
    # Drive the TLS object over the socket until fn succeeds.
    while True:
        try:
            r = fn(*a)
            raw.sendall(out.read())
            return r
        except ssl.SSLWantReadError:
            raw.sendall(out.read())
            data = raw.recv(65536)
            if not data:
                raise ConnectionError("closed")
            inc.write(data)

t_hello = time.time()
try:
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = out.read()
    if split:
        raw.sendall(hello[:split]); time.sleep(0.001); raw.sendall(hello[split:])
    else:
        raw.sendall(hello)
    step(tls.do_handshake)
    step(tls.write, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    ok = step(tls.read, 100).startswith(b"HTTP/1.1 200")
    outcome = "completed" if ok else "broken"
except (OSError, ssl.SSLError, ConnectionError):
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


def client(ip, name, split=0):
    out = sh(sys.executable, "-c", CLIENT, ip, name, str(split))
    return json.loads(out.stdout)


def restart_server(delay_ms):
    """(Re)start the namespace TLS server with the given reply delay."""
    pids = sh("ip", "netns", "pids", NS).stdout.split()
    for pid in pids:
        sh("kill", pid, check=False)
    time.sleep(0.5)
    subprocess.Popen(
        ["ip", "netns", "exec", NS, sys.executable, str(ROOT / "tls_server.py"),
         "/tmp/dpig-cert.pem", "/tmp/dpig-key.pem", str(delay_ms)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    time.sleep(1.0)


def state(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state?events=all") as r:
        return json.load(r)


def run_mode(spec, trials, idle_timeout, port, delay_ms=0, split=0):
    mode, _, fallback = spec.partition(":")
    app = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dpiguard.cli",
            "--iface",
            "veth0",
            "--mode",
            mode,
            "--fastpath-fallback",
            fallback or "early",
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
            blocked = client(f"10.0.1.{i}", f"t{i}.blocked.test", split)
            control = client(f"10.0.2.{i}", f"c{i}.allowed.test", split)
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
                "mode": spec,
                "delay_ms": delay_ms,
                "split": split,
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
    parser.add_argument("--delays", default="0", help="comma-separated server reply delays, ms")
    parser.add_argument("--split", type=int, default=0)
    parser.add_argument("--out", default="time_to_block.csv")
    args = parser.parse_args()
    prepare_addresses(args.trials)
    rows = []
    port = 5100
    for delay in [int(d) for d in args.delays.split(",")]:
        restart_server(delay)
        for mode in args.modes.split(","):
            rows += run_mode(mode, args.trials, args.idle_timeout, port, delay, args.split)
            port += 1
            print(f"delay {delay} ms, {mode}: done", flush=True)
    out = ROOT / "results" / args.out
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for mode, delay in sorted({(r["mode"], r["delay_ms"]) for r in rows}):
        sub = [r for r in rows if r["mode"] == mode and r["delay_ms"] == delay]
        ttb = sorted(r["time_to_block_ms"] for r in sub if r["time_to_block_ms"] != "")
        stopped = sum(r["first_connection"] == "blocked" for r in sub)
        controls = sum(r["control_connection"] == "completed" for r in sub)
        if ttb:
            print(
                f"{mode:15} delay={delay:3} ms n={len(sub)} enforced={len(ttb)} "
                f"median TTB={statistics.median(ttb):8.1f} ms "
                f"p90={ttb[int(0.9 * (len(ttb) - 1))]:8.1f} ms "
                f"first conn blocked={stopped}/{len(sub)} controls ok={controls}/{len(sub)}"
            )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
