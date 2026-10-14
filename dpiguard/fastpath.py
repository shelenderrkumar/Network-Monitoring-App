"""Fast path: read TLS server names the moment a ClientHello crosses the interface.

NFStream captures through libpcap's buffered (TPACKET_V3) mode, which hands packets to
user space in blocks on a ~1 s timer, so a plugin sees a ClientHello 0-1000 ms after it
was sent (measured: median ~500 ms). That is long enough for the whole TLS handshake to
finish. The fast path avoids the buffer: a plain AF_PACKET socket with a classic-BPF
filter compiled into the kernel, so user space wakes up only for TLS ClientHello
segments and parses the SNI immediately. NFStream keeps doing full DPI and accounting.

Scope: IPv4 TCP to port 443 with the ClientHello in one segment (the common case; a
ClientHello split across segments, e.g. with large post-quantum key shares, falls back
to the NFStream path).
"""

import ctypes
import ipaddress
import logging
import socket
import struct
import threading
import time
from collections.abc import Callable

logger = logging.getLogger(__name__)

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26

# tcpdump -dd 'tcp dst port 443 and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16
#              and tcp[((tcp[12:1] & 0xf0) >> 2) + 5:1] = 0x01'
# = IPv4, TCP, dst port 443, first payload byte = TLS handshake record (0x16) and the
#   handshake type = ClientHello (0x01). Unfragmented packets only.
CLIENT_HELLO_FILTER = [
    (0x28, 0, 0, 0x0000000C), (0x15, 25, 0, 0x000086DD), (0x15, 0, 24, 0x00000800),
    (0x30, 0, 0, 0x00000017), (0x15, 0, 22, 0x00000006), (0x28, 0, 0, 0x00000014),
    (0x45, 20, 0, 0x00001FFF), (0xB1, 0, 0, 0x0000000E), (0x48, 0, 0, 0x00000010),
    (0x15, 0, 17, 0x000001BB), (0x50, 0, 0, 0x0000001A), (0x54, 0, 0, 0x000000F0),
    (0x74, 0, 0, 0x00000002), (0x0C, 0, 0, 0x00000000), (0x07, 0, 0, 0x00000000),
    (0x50, 0, 0, 0x0000000E), (0x15, 0, 10, 0x00000016), (0xB1, 0, 0, 0x0000000E),
    (0x50, 0, 0, 0x0000001A), (0x54, 0, 0, 0x000000F0), (0x74, 0, 0, 0x00000002),
    (0x04, 0, 0, 0x00000005), (0x0C, 0, 0, 0x00000000), (0x07, 0, 0, 0x00000000),
    (0x50, 0, 0, 0x0000000E), (0x15, 0, 1, 0x00000001), (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
]  # fmt: skip


def parse_sni(tls: bytes) -> str | None:
    """Extract the server_name from a TLS ClientHello record, or None."""
    try:
        if len(tls) < 43 or tls[0] != 0x16 or tls[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        session_len = tls[pos]
        pos += 1 + session_len
        (suites_len,) = struct.unpack_from("!H", tls, pos)
        pos += 2 + suites_len
        compression_len = tls[pos]
        pos += 1 + compression_len
        (ext_total,) = struct.unpack_from("!H", tls, pos)
        pos += 2
        end = min(pos + ext_total, len(tls))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", tls, pos)
            pos += 4
            if ext_type == 0:  # server_name
                # list length (2), name type (1), name length (2), name
                name_type = tls[pos + 2]
                (name_len,) = struct.unpack_from("!H", tls, pos + 3)
                if name_type == 0:
                    name = tls[pos + 5 : pos + 5 + name_len]
                    return name.decode("ascii").lower() if len(name) == name_len else None
                return None
            pos += ext_len
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def parse_frame(frame: bytes) -> tuple[str, str] | None:
    """Ethernet frame carrying a ClientHello -> (server name, server IP)."""
    if len(frame) < 14 + 20 + 20 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    tcp = 14 + ihl
    data_offset = (frame[tcp + 12] >> 4) * 4
    name = parse_sni(frame[tcp + data_offset :])
    if name is None:
        return None
    return name, str(ipaddress.IPv4Address(frame[30:34]))


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8),
                ("k", ctypes.c_uint32)]  # fmt: skip


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_SockFilter))]


def _attach_filter(sock: socket.socket) -> None:
    program = (_SockFilter * len(CLIENT_HELLO_FILTER))(*CLIENT_HELLO_FILTER)
    fprog = _SockFprog(len(CLIENT_HELLO_FILTER), program)
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fprog))
    # Drain anything queued before the filter was attached.
    sock.setblocking(False)
    try:
        while sock.recv(65535):
            pass
    except BlockingIOError:
        pass
    sock.setblocking(True)


def run_fastpath(
    iface: str,
    on_server_name: Callable[[str, str, float], None],
    stop: threading.Event | None = None,
) -> None:
    """Call ``on_server_name(name, server_ip, seen_at)`` for every ClientHello on ``iface``."""
    stop = stop or threading.Event()
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    _attach_filter(sock)
    sock.settimeout(0.5)
    logger.info("Fast path listening for TLS ClientHellos on %s", iface)
    try:
        while not stop.is_set():
            try:
                frame = sock.recv(65535)
            except TimeoutError:
                continue
            except OSError as exc:  # interface removed or down
                if not stop.is_set():
                    logger.error("Fast path stopped on %s: %s", iface, exc)
                break
            seen_at = time.time()
            parsed = parse_frame(frame)
            if parsed:
                on_server_name(parsed[0], parsed[1], seen_at)
    finally:
        sock.close()
