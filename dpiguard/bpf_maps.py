"""Minimal, dependency-free access to pinned eBPF maps through the bpf(2) syscall.

Only the five commands the controller needs are implemented. This replaces the
original BCC dependency, which compiled C at runtime and therefore required
kernel headers on every machine.
"""

import ctypes
import os
import platform
from functools import cache

_SYSCALL_NR = {"x86_64": 321, "aarch64": 280, "armv7l": 386, "riscv64": 280}

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_OBJ_GET = 7

BPF_ANY = 0


class _MapElemAttr(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),  # also next_key for GET_NEXT_KEY
        ("flags", ctypes.c_uint64),
    ]


class _ObjGetAttr(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


_libc = ctypes.CDLL(None, use_errno=True)


def _bpf(cmd: int, attr: ctypes.Structure) -> int:
    nr = _SYSCALL_NR.get(platform.machine())
    if nr is None:
        raise OSError(f"bpf syscall number unknown for {platform.machine()}")
    ret = _libc.syscall(nr, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


@cache
def possible_cpus() -> int:
    """Number of CPU slots in a per-CPU map value (from /sys, e.g. '0-7')."""
    with open("/sys/devices/system/cpu/possible") as f:
        spec = f.read().strip()
    total = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        total += int(hi or lo) - int(lo) + 1
    return total


class PinnedMap:
    """A pinned BPF map with fixed key and value sizes."""

    def __init__(self, path: str, key_size: int, value_size: int, per_cpu: bool = False):
        path_buf = ctypes.create_string_buffer(path.encode())
        attr = _ObjGetAttr(pathname=ctypes.addressof(path_buf))
        self.fd = _bpf(BPF_OBJ_GET, attr)
        self.key_size = key_size
        # Per-CPU values are one 8-byte-aligned slot per possible CPU.
        slot = (value_size + 7) & ~7
        self.value_size = slot * possible_cpus() if per_cpu else value_size
        self.slot = slot

    def close(self) -> None:
        os.close(self.fd)

    def _attr(self, key: bytes, value=None, flags: int = 0):
        assert len(key) == self.key_size, "wrong key size"
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        vbuf = value if value is not None else ctypes.create_string_buffer(self.value_size)
        attr = _MapElemAttr(
            map_fd=self.fd, key=ctypes.addressof(kbuf), value=ctypes.addressof(vbuf), flags=flags
        )
        return attr, kbuf, vbuf

    def update(self, key: bytes, value: bytes) -> None:
        vbuf = ctypes.create_string_buffer(value, self.value_size)
        attr, _k, _v = self._attr(key, vbuf, BPF_ANY)
        _bpf(BPF_MAP_UPDATE_ELEM, attr)

    def lookup(self, key: bytes) -> bytes | None:
        attr, _k, vbuf = self._attr(key)
        try:
            _bpf(BPF_MAP_LOOKUP_ELEM, attr)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno == 2:  # ENOENT
                return None
            raise
        return vbuf.raw

    def delete(self, key: bytes) -> bool:
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        # The kernel rejects DELETE unless every attribute after `key` is zero.
        attr = _MapElemAttr(map_fd=self.fd, key=ctypes.addressof(kbuf))
        try:
            _bpf(BPF_MAP_DELETE_ELEM, attr)
        except OSError as exc:
            if exc.errno == 2:
                return False
            raise
        return True

    def all_keys(self) -> list[bytes]:
        out: list[bytes] = []
        current = None
        while True:
            kbuf = ctypes.create_string_buffer(current or b"\0" * self.key_size, self.key_size)
            nbuf = ctypes.create_string_buffer(self.key_size)
            attr = _MapElemAttr(
                map_fd=self.fd,
                key=0 if current is None else ctypes.addressof(kbuf),
                value=ctypes.addressof(nbuf),
            )
            try:
                _bpf(BPF_MAP_GET_NEXT_KEY, attr)
            except OSError as exc:
                if exc.errno == 2:
                    return out
                raise
            current = nbuf.raw
            out.append(current)
