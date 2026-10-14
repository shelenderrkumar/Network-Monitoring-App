"""Connects flow inspection, the domain policy, the enforcer and live statistics.

Three decision modes (compared in the evaluation):

* ``expiry`` - the original design: a flow's server name is acted on when NFStream
  exports the flow, i.e. after it has been idle for ``idle_timeout`` seconds (or reached
  ``active_timeout``). The first connection to a blocked domain always completes.
* ``early``  - an NFStream plugin runs on every packet and reports the server name as
  soon as nDPI extracts it (TLS ClientHello SNI, QUIC, DNS, HTTP Host), usually on the
  connection's 4th packet. Limited by libpcap's buffered capture (0-1 s delay).
* ``fastpath`` - a filtered AF_PACKET socket parses the TLS ClientHello the moment it is
  sent (see ``fastpath.py``); NFStream still runs for statistics and other protocols.
"""

import logging
import multiprocessing as mp
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass

from dpiguard.enforcers import Enforcer
from dpiguard.policy import DomainPolicy
from dpiguard.stats import TrafficStats

logger = logging.getLogger(__name__)


@dataclass
class Enforcement:
    domain: str
    ip: str
    rule: str
    detected_at: float  # when the server name became known (packet time, early mode)
    enforced_at: float  # when the IP was written to the enforcer
    mode: str


class Controller:
    def __init__(self, policy: DomainPolicy, enforcer: Enforcer, stats: TrafficStats | None = None):
        self.policy = policy
        self.enforcer = enforcer
        self.stats = stats or TrafficStats()
        self.events: deque[Enforcement] = deque(maxlen=1000)
        self._lock = threading.Lock()

    # -- decisions ----------------------------------------------------------------------
    def on_server_name(self, domain: str, ip: str, detected_at: float, mode: str) -> bool:
        """Called whenever a (server name, server IP) pair is seen. Returns True if blocked."""
        if not domain:
            return False
        decision = self.policy.observe(domain, ip)
        if not decision.block:
            return False
        with self._lock:
            already = any(e.ip == ip for e in self.events if e.rule == decision.rule)
            self.enforcer.block(ip)
            if not already:
                event = Enforcement(
                    decision.domain, ip, decision.rule, detected_at, time.time(), mode
                )
                self.events.append(event)
                logger.info("blocked %s (%s) via rule %s [%s]", ip, domain, decision.rule, mode)
        return True

    def on_flow_expired(self, flow, mode: str) -> None:
        """Account the flow and, as a fallback, enforce on its server name.

        In ``early``/``fastpath`` modes this catches anything the fast detectors missed
        (QUIC, a ClientHello split across segments, a plugin event lost under load) and
        records the (domain, IP) pair so rules added later cover IPs already seen.
        """
        name = flow.requested_server_name or ""
        if name:
            self.stats.record_flow(
                name, flow.application_name, flow.bidirectional_packets, flow.bidirectional_bytes
            )
            self.on_server_name(
                name, flow.dst_ip, time.time(), "expiry" if mode == "expiry" else "fallback"
            )

    # -- rule management (dashboard / API) --------------------------------------------------
    def add_rule(self, rule: str) -> list[str]:
        ips = self.policy.add_rule(rule)
        for ip in ips:
            self.enforcer.block(ip)
        return sorted(ips)

    def remove_rule(self, rule: str) -> list[str]:
        ips = self.policy.remove_rule(rule)
        for ip in ips:
            self.enforcer.unblock(ip)
        return sorted(ips)

    def snapshot(self) -> dict:
        return {
            "rules": self.policy.rules,
            "domains": self.stats.top(),
            "totals": self.stats.totals(),
            "history": self.stats.history(),
            "blocked": self.enforcer.blocked(),
            "kernel": self.enforcer.totals(),
            "collateral": self.policy.collateral(),
            "events": [asdict(e) for e in list(self.events)[-50:]],
            "enforcer": self.enforcer.name,
        }


def _early_plugin(queue):
    from nfstream import NFPlugin

    class EarlyServerName(NFPlugin):
        """Runs inside the NFStream meter process on every packet of every flow."""

        def on_init(self, packet, flow):
            flow.udps.name_reported = False

        def on_update(self, packet, flow):
            if not flow.udps.name_reported and flow.requested_server_name:
                flow.udps.name_reported = True
                self.queue.put((flow.requested_server_name, flow.dst_ip, packet.time / 1000))

    return EarlyServerName(queue=queue)


def run_capture(
    controller: Controller,
    iface: str,
    mode: str = "early",
    idle_timeout: int = 5,
    active_timeout: int = 120,
    stop: threading.Event | None = None,
) -> None:
    """Capture on ``iface`` until ``stop`` is set (blocking; run it in a thread)."""
    from nfstream import NFStreamer

    if mode not in {"early", "expiry", "fastpath"}:
        raise ValueError("mode must be 'early', 'expiry' or 'fastpath'")
    stop = stop or threading.Event()
    queue = mp.get_context("fork").Queue() if mode == "early" else None

    def consume_early_events():
        while not stop.is_set():
            try:
                name, ip, detected_at = queue.get(timeout=0.5)
            except Exception:
                continue
            controller.on_server_name(name, ip, detected_at, "early")

    if queue is not None:
        threading.Thread(target=consume_early_events, daemon=True).start()
    if mode == "fastpath":
        from dpiguard.fastpath import run_fastpath

        def on_name(name, ip, seen_at):
            controller.on_server_name(name, ip, seen_at, "fastpath")

        threading.Thread(target=run_fastpath, args=(iface, on_name, stop), daemon=True).start()

    streamer = NFStreamer(
        source=iface,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        statistical_analysis=False,
        udps=_early_plugin(queue) if queue is not None else None,
        n_meters=1,
    )
    logger.info("Capturing on %s (%s mode)", iface, mode)
    for flow in streamer:
        controller.on_flow_expired(flow, mode)
        if stop.is_set():
            break
