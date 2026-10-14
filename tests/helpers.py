import contextlib
import socket
import ssl
import struct


def client_hello(server_name: str | None) -> bytes:
    """A real TLS ClientHello produced by Python's ssl module (no network)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def ethernet_frame(payload: bytes, src="10.0.0.1", dst="10.0.0.2", dport=443) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 51515, dport, 1, 0, 5 << 4, 0x18, 64240, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # fmt: skip
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
