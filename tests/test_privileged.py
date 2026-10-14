"""Real-kernel tests: XDP on a veth pair with the peer in a network namespace.

Run as root on Linux with clang and iproute2:  sudo pytest -m privileged
"""

import os
import shutil
import subprocess
import threading
import time

import pytest

pytestmark = [
    pytest.mark.privileged,
    pytest.mark.skipif(
        os.geteuid() != 0 or not shutil.which("clang") or not shutil.which("ip"),
        reason="needs root, clang and iproute2",
    ),
]

NS, HOST_IF, PEER_IF = "dpig-test", "dpig0", "dpig1"


def sh(*cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"{' '.join(cmd)[:120]}: {result.stderr.strip()}"


@pytest.fixture
def testbed():
    subprocess.run(["ip", "netns", "del", NS], capture_output=True)
    subprocess.run(["ip", "link", "del", HOST_IF], capture_output=True)
    sh("ip", "netns", "add", NS)
    sh("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF)
    sh("ip", "link", "set", PEER_IF, "netns", NS)
    sh("ip", "addr", "add", "10.99.0.1/24", "dev", HOST_IF)
    sh("ip", "link", "set", HOST_IF, "up")
    sh("ip", "netns", "exec", NS, "ip", "addr", "add", "10.99.0.2/24", "dev", PEER_IF)
    sh("ip", "netns", "exec", NS, "ip", "link", "set", PEER_IF, "up")
    yield
    subprocess.run(["ip", "netns", "del", NS], capture_output=True)
    subprocess.run(["ip", "link", "del", HOST_IF], capture_output=True)


def send_udp(count):
    code = (
        "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"for _ in range({count}): s.sendto(b'x' * 32, ('10.99.0.1', 9))"
    )
    sh("ip", "netns", "exec", NS, "python3", "-c", code)


@pytest.mark.parametrize("kind", ["xdp", "nft"])
def test_enforcer_drops_only_blocked_source(testbed, kind):
    from dpiguard.enforcers import make_enforcer

    enforcer = make_enforcer(kind, HOST_IF)
    try:
        enforcer.block("10.99.0.2")
        send_udp(200)
        assert enforcer.blocked()["10.99.0.2"]["packets"] == 200
        enforcer.unblock("10.99.0.2")
        send_udp(50)
        assert "10.99.0.2" not in enforcer.blocked()
    finally:
        enforcer.close()


def test_fastpath_sees_client_hello_immediately(testbed):
    from dpiguard.fastpath import run_fastpath
    from tests.helpers import client_hello

    seen, stop = [], threading.Event()
    threading.Thread(
        target=run_fastpath, args=(HOST_IF, lambda *a: seen.append(a), stop), daemon=True
    ).start()
    server = subprocess.Popen(
        ["python3", "-u", "-c",
         "import socket; s = socket.socket(); "
         "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
         "s.bind(('10.99.0.1', 443)); s.listen(); "
         "print('ready'); c, _ = s.accept(); c.recv(4096)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert server.stdout.readline().strip() == "ready", server.stderr.read()
        hello = client_hello("blocked.example.com")
        sent_at = time.time()
        client = (
            "import socket, time\n"
            "for _ in range(50):  # wait for the listener to come up\n"
            "    try:\n"
            "        s = socket.create_connection(('10.99.0.1', 443), timeout=2); break\n"
            "    except ConnectionRefusedError:\n"
            "        time.sleep(0.05)\n"
            f"s.sendall({hello!r})\n"
        )
        sh("ip", "netns", "exec", NS, "python3", "-c", client)
        deadline = time.time() + 2
        while not seen and time.time() < deadline:
            time.sleep(0.01)
    finally:
        stop.set()
        server.kill()
        server.wait()
    name, server_ip, seen_at = seen[0]
    assert (name, server_ip) == ("blocked.example.com", "10.99.0.1")
    assert seen_at - sent_at < 0.5  # no capture-buffer delay
