import pytest

from dpiguard.fastpath import CLIENT_HELLO_FILTER, parse_frame, parse_sni
from tests.helpers import client_hello, ethernet_frame


@pytest.mark.parametrize("name", ["www.youtube.com", "a.b.c.example.org", "x.io"])
def test_parse_sni_from_real_client_hello(name):
    assert parse_sni(client_hello(name)) == name


def test_client_hello_without_sni():
    assert parse_sni(client_hello(None)) is None


@pytest.mark.parametrize(
    "data", [b"", b"\x17\x03\x03\x00\x10" + b"\x00" * 60, client_hello("x.com")[:40]]
)
def test_non_client_hello_or_truncated_input_is_ignored(data):
    assert parse_sni(data) is None


def test_parse_frame_returns_name_and_server_ip():
    frame = ethernet_frame(client_hello("www.youtube.com"), dst="142.250.1.1")
    assert parse_frame(frame) == ("www.youtube.com", "142.250.1.1")


def test_parse_frame_ignores_non_ipv4():
    frame = bytearray(ethernet_frame(client_hello("x.com")))
    frame[12:14] = b"\x86\xdd"
    assert parse_frame(bytes(frame)) is None


def test_filter_program_is_well_formed():
    assert len(CLIENT_HELLO_FILTER) == 28
    assert CLIENT_HELLO_FILTER[-1] == (0x06, 0, 0, 0)  # final instruction rejects
