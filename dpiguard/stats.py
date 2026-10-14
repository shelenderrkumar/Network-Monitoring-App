"""Live traffic statistics per domain, plus a per-second packet-rate history."""

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass


@dataclass
class DomainStats:
    domain: str
    application: str = ""
    flows: int = 0
    packets: int = 0
    bytes: int = 0
    last_seen: float = 0.0


class TrafficStats:
    def __init__(self, history_seconds: int = 60, clock=time.time):
        self._lock = threading.Lock()
        self._clock = clock
        self._domains: dict[str, DomainStats] = {}
        self._history: deque[tuple[int, int]] = deque(maxlen=history_seconds)

    def record_flow(self, domain: str, application: str, packets: int, nbytes: int) -> None:
        now = self._clock()
        with self._lock:
            entry = self._domains.setdefault(domain, DomainStats(domain))
            entry.application = application or entry.application
            entry.flows += 1
            entry.packets += packets
            entry.bytes += nbytes
            entry.last_seen = now
            second = int(now)
            if self._history and self._history[-1][0] == second:
                self._history[-1] = (second, self._history[-1][1] + packets)
            else:
                self._history.append((second, packets))

    def top(self, n: int = 50) -> list[dict]:
        with self._lock:
            ranked = sorted(self._domains.values(), key=lambda d: d.packets, reverse=True)
            return [asdict(d) for d in ranked[:n]]

    def history(self) -> list[tuple[int, int]]:
        with self._lock:
            return list(self._history)

    def totals(self) -> dict[str, int]:
        with self._lock:
            return {
                "domains": len(self._domains),
                "flows": sum(d.flows for d in self._domains.values()),
                "packets": sum(d.packets for d in self._domains.values()),
                "bytes": sum(d.bytes for d in self._domains.values()),
            }
