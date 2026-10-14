from types import SimpleNamespace

from dpiguard.controller import Controller
from dpiguard.enforcers import MemoryEnforcer
from dpiguard.policy import DomainPolicy
from dpiguard.web import create_app


def make(rules=()):
    return Controller(DomainPolicy(list(rules)), MemoryEnforcer())


def flow(name, ip, packets=10, app="TLS"):
    return SimpleNamespace(
        requested_server_name=name, dst_ip=ip, application_name=app,
        bidirectional_packets=packets, bidirectional_bytes=packets * 100,
    )  # fmt: skip


def test_blocked_name_is_enforced_once_and_logged():
    ctl = make(["youtube.com"])
    assert ctl.on_server_name("www.youtube.com", "10.0.0.2", 100.0, "fastpath")
    assert ctl.on_server_name("m.youtube.com", "10.0.0.2", 101.0, "fastpath")
    assert ctl.enforcer.blocked() == {"10.0.0.2": {"packets": 0, "bytes": 0}}
    assert len(ctl.events) == 1 and ctl.events[0].mode == "fastpath"


def test_allowed_name_is_not_enforced():
    ctl = make(["youtube.com"])
    assert not ctl.on_server_name("example.org", "10.0.0.3", 1.0, "early")
    assert ctl.enforcer.calls == []


def test_expired_flows_are_counted_and_enforced_as_fallback():
    ctl = make(["youtube.com"])
    ctl.on_flow_expired(flow("example.org", "10.0.0.3"), "fastpath")
    assert ctl.enforcer.calls == []
    ctl.on_flow_expired(flow("www.youtube.com", "10.0.0.2"), "fastpath")  # fast path missed it
    assert ctl.enforcer.calls == [("block", "10.0.0.2")] and ctl.events[0].mode == "fallback"
    ctl.on_flow_expired(flow("www.youtube.com", "10.0.0.2"), "expiry")
    assert len(ctl.events) == 1  # already enforced, not logged twice
    assert ctl.stats.totals()["flows"] == 3


def test_rule_changes_reach_the_enforcer():
    ctl = make()
    ctl.on_server_name("www.youtube.com", "10.0.0.2", 1.0, "fastpath")
    assert ctl.add_rule("youtube.com") == ["10.0.0.2"]
    assert ctl.remove_rule("youtube.com") == ["10.0.0.2"]
    assert ctl.enforcer.calls == [("block", "10.0.0.2"), ("unblock", "10.0.0.2")]


def test_api_flow_and_auth():
    ctl = make()
    ctl.on_flow_expired(flow("www.youtube.com", "10.0.0.2"), "fastpath")
    client = create_app(ctl, password="pw").test_client()
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/state").status_code == 401
    auth = {"Authorization": "Basic dXNlcjpwdw=="}  # user:pw
    assert client.post("/api/rules", json={"rule": "youtube.com"}, headers=auth).status_code == 201
    state = client.get("/api/state", headers=auth).get_json()
    assert state["rules"] == ["youtube.com"] and "10.0.0.2" in state["blocked"]
    assert client.post("/api/rules", json={"rule": ""}, headers=auth).status_code == 400
    assert client.delete("/api/rules/youtube.com", headers=auth).get_json()["unblocked"] == [
        "10.0.0.2"
    ]
    assert client.get("/block_it/x").status_code == 404  # no state change via GET links
