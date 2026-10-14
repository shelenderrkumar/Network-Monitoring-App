"""Enforcers turn "block this IP" into packets being dropped.

* ``XdpEnforcer``  - the system's enforcer: an XDP program on the interface's receive path.
* ``NftEnforcer``  - baseline for the evaluation: an nftables set on the netdev ingress hook,
                     the earliest point netfilter can drop a packet.
* ``MemoryEnforcer`` - records calls; used by tests and dry runs.
"""

import ipaddress
import logging
import shutil
import struct
import subprocess
import threading
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

BPF_DIR = Path(__file__).resolve().parent / "bpf"
BPF_SOURCE = BPF_DIR / "xdp_blocklist.c"
PIN_DIR = Path("/sys/fs/bpf/xdp/globals")
COUNTERS = struct.Struct("=QQ")  # packets, bytes


class Enforcer(Protocol):
    name: str

    def block(self, ip: str) -> None: ...
    def unblock(self, ip: str) -> None: ...
    def blocked(self) -> dict[str, dict[str, int]]: ...
    def totals(self) -> dict[str, int]: ...
    def close(self) -> None: ...


class MemoryEnforcer:
    name = "memory"

    def __init__(self):
        self._blocked: dict[str, dict[str, int]] = {}
        self.calls: list[tuple[str, str]] = []

    def block(self, ip):
        self.calls.append(("block", ip))
        self._blocked.setdefault(ip, {"packets": 0, "bytes": 0})

    def unblock(self, ip):
        self.calls.append(("unblock", ip))
        self._blocked.pop(ip, None)

    def blocked(self):
        return dict(self._blocked)

    def totals(self):
        dropped = sum(c["packets"] for c in self._blocked.values())
        return {"passed_packets": 0, "dropped_packets": dropped}

    def close(self):
        pass


def _run(*cmd: str, stdin: str | None = None) -> str:
    result = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
    return result.stdout


def build_bpf_object(output: Path | None = None) -> Path:
    """Compile the XDP program with clang (needs clang + libbpf headers, not kernel headers)."""
    output = output or BPF_DIR / "xdp_blocklist.o"
    if output.exists() and output.stat().st_mtime >= BPF_SOURCE.stat().st_mtime:
        return output
    if shutil.which("clang") is None:
        raise RuntimeError("clang is required to build the XDP program")
    arch = _run("uname", "-m").strip()
    _run(
        "clang", "-O2", "-g", "-Wall", "-target", "bpf",
        f"-I/usr/include/{arch}-linux-gnu", "-c", str(BPF_SOURCE), "-o", str(output),
    )  # fmt: skip
    return output


def _key(ip: str) -> tuple[str, bytes]:
    addr = ipaddress.ip_address(ip)
    return ("v4" if addr.version == 4 else "v6"), addr.packed  # packed = network byte order


class XdpEnforcer:
    """Attaches the XDP blocklist to an interface and manages its pinned maps."""

    name = "xdp"

    def __init__(self, iface: str, mode: str = "drv", reset: bool = True):
        from dpiguard.bpf_maps import PinnedMap  # Linux-only

        if mode not in {"drv", "generic", "offload"}:
            raise ValueError("mode must be drv, generic or offload")
        self.iface, self.mode = iface, mode
        self._lock = threading.Lock()
        if not Path("/sys/fs/bpf").is_mount():
            _run("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")
        if reset:  # stale pins from an older program version would be reused otherwise
            for pin in ("blocklist_v4", "blocklist_v6", "xdp_stats"):
                (PIN_DIR / pin).unlink(missing_ok=True)
        obj = build_bpf_object()
        _run("ip", "link", "set", "dev", iface, f"xdp{mode}", "obj", str(obj), "sec", "xdp")
        self._maps = {
            "v4": PinnedMap(str(PIN_DIR / "blocklist_v4"), 4, COUNTERS.size),
            "v6": PinnedMap(str(PIN_DIR / "blocklist_v6"), 16, COUNTERS.size),
        }
        self._stats = PinnedMap(str(PIN_DIR / "xdp_stats"), 4, COUNTERS.size, per_cpu=True)
        logger.info("XDP blocklist attached to %s (%s mode)", iface, mode)

    def block(self, ip: str) -> None:
        family, key = _key(ip)
        with self._lock:
            if self._maps[family].lookup(key) is None:  # keep existing drop counters
                self._maps[family].update(key, COUNTERS.pack(0, 0))

    def unblock(self, ip: str) -> None:
        family, key = _key(ip)
        with self._lock:
            self._maps[family].delete(key)

    def blocked(self) -> dict[str, dict[str, int]]:
        out = {}
        with self._lock:
            for bpf_map in self._maps.values():
                for key in bpf_map.all_keys():
                    value = bpf_map.lookup(key)
                    if value is None:
                        continue
                    packets, nbytes = COUNTERS.unpack(value)
                    ip = str(ipaddress.ip_address(key))
                    out[ip] = {"packets": packets, "bytes": nbytes}
        return out

    def totals(self) -> dict[str, int]:
        from dpiguard.bpf_maps import possible_cpus

        result = {}
        for index, label in ((0, "passed"), (1, "dropped")):
            raw = self._stats.lookup(struct.pack("=I", index)) or b""
            packets = sum(
                COUNTERS.unpack_from(raw, cpu * self._stats.slot)[0]
                for cpu in range(possible_cpus())
                if len(raw) >= (cpu + 1) * self._stats.slot
            )
            result[f"{label}_packets"] = packets
        return result

    def close(self) -> None:
        subprocess.run(["ip", "link", "set", "dev", self.iface, f"xdp{self.mode}", "off"])
        for bpf_map in (*self._maps.values(), self._stats):
            bpf_map.close()
        logger.info("XDP detached from %s", self.iface)


class NftEnforcer:
    """Baseline: nftables sets on the netdev ingress hook of the interface."""

    name = "nft"
    TABLE = "dpiguard"

    def __init__(self, iface: str):
        self.iface = iface
        subprocess.run(["nft", "delete", "table", "netdev", self.TABLE], capture_output=True)
        _run(
            "nft",
            "-f",
            "-",
            stdin=f"""
table netdev {self.TABLE} {{
    set blocked4 {{ type ipv4_addr; counter; }}
    set blocked6 {{ type ipv6_addr; counter; }}
    chain ingress {{
        type filter hook ingress device "{iface}" priority -500; policy accept;
        ip saddr @blocked4 drop
        ip daddr @blocked4 drop
        ip6 saddr @blocked6 drop
        ip6 daddr @blocked6 drop
    }}
}}""",
        )

    def _set(self, ip: str) -> str:
        return "blocked4" if ipaddress.ip_address(ip).version == 4 else "blocked6"

    def block(self, ip: str) -> None:
        _run("nft", "add", "element", "netdev", self.TABLE, self._set(ip), f"{{ {ip} }}")

    def unblock(self, ip: str) -> None:
        subprocess.run(
            ["nft", "delete", "element", "netdev", self.TABLE, self._set(ip), f"{{ {ip} }}"],
            capture_output=True,
        )

    def blocked(self) -> dict[str, dict[str, int]]:
        import json

        out = {}
        for set_name in ("blocked4", "blocked6"):
            data = json.loads(_run("nft", "-j", "list", "set", "netdev", self.TABLE, set_name))
            for item in data["nftables"]:
                for element in item.get("set", {}).get("elem", []):
                    elem = element.get("elem", element)
                    counter = elem.get("counter", {}) if isinstance(elem, dict) else {}
                    ip = elem.get("val") if isinstance(elem, dict) else elem
                    out[str(ip)] = {
                        "packets": counter.get("packets", 0),
                        "bytes": counter.get("bytes", 0),
                    }
        return out

    def totals(self) -> dict[str, int]:
        dropped = sum(v["packets"] for v in self.blocked().values())
        return {"passed_packets": -1, "dropped_packets": dropped}

    def close(self) -> None:
        subprocess.run(["nft", "delete", "table", "netdev", self.TABLE], capture_output=True)


def make_enforcer(kind: str, iface: str, xdp_mode: str = "drv") -> Enforcer:
    if kind == "xdp":
        return XdpEnforcer(iface, xdp_mode)
    if kind == "nft":
        return NftEnforcer(iface)
    if kind == "memory":
        return MemoryEnforcer()
    raise ValueError(f"unknown enforcer {kind!r}")
