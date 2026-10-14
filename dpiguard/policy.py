"""Which domains are blocked, and which IP addresses that implies.

Enforcement happens on IP addresses (XDP sees packets, not names), but people block
domains. The policy keeps both views consistent:

* a rule ``example.com`` matches ``example.com`` and every subdomain;
* every observed (domain, server IP) pair is remembered, so blocking a rule takes effect
  immediately for IPs already seen, and unblocking removes exactly the IPs that no
  remaining rule still needs (the original code re-resolved the name with DNS, which
  often returned a different IP and left the old one blocked forever);
* an IP that serves both a blocked and an allowed domain (shared hosting, CDNs) is
  reported as collateral, because blocking it also blocks the allowed domain.
"""

import threading
from collections import defaultdict
from dataclasses import dataclass


def normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".").removeprefix("*.")


def matches(rule: str, domain: str) -> bool:
    return domain == rule or domain.endswith("." + rule)


@dataclass(frozen=True)
class Decision:
    block: bool
    ip: str
    domain: str
    rule: str | None = None


class DomainPolicy:
    def __init__(self, rules: list[str] | None = None):
        self._lock = threading.RLock()
        self._rules: set[str] = set()
        self._ips_by_domain: dict[str, set[str]] = defaultdict(set)
        self._domains_by_ip: dict[str, set[str]] = defaultdict(set)
        for rule in rules or []:
            self.add_rule(rule)

    # -- queries ---------------------------------------------------------------------
    @property
    def rules(self) -> list[str]:
        with self._lock:
            return sorted(self._rules)

    def rule_for(self, domain: str) -> str | None:
        domain = normalize(domain)
        with self._lock:
            # Most specific rule wins when several match.
            hits = [r for r in self._rules if matches(r, domain)]
            return max(hits, key=len) if hits else None

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            return any(self.rule_for(d) for d in self._domains_by_ip.get(ip, ()))

    def blocked_ips(self) -> set[str]:
        with self._lock:
            return {ip for ip in self._domains_by_ip if self.is_ip_blocked(ip)}

    def collateral(self) -> dict[str, list[str]]:
        """Blocked IPs that also serve allowed domains -> those allowed domains."""
        with self._lock:
            out = {}
            for ip in self.blocked_ips():
                allowed = sorted(d for d in self._domains_by_ip[ip] if not self.rule_for(d))
                if allowed:
                    out[ip] = allowed
            return out

    # -- updates ---------------------------------------------------------------------
    def observe(self, domain: str, ip: str) -> Decision:
        """Record that ``domain`` was served from ``ip`` and decide whether to block it."""
        domain = normalize(domain)
        with self._lock:
            self._ips_by_domain[domain].add(ip)
            self._domains_by_ip[ip].add(domain)
            rule = self.rule_for(domain)
        return Decision(block=rule is not None, ip=ip, domain=domain, rule=rule)

    def add_rule(self, rule: str) -> set[str]:
        """Add a rule; returns IPs that must be blocked now (already observed)."""
        rule = normalize(rule)
        if not rule or " " in rule:
            raise ValueError(f"invalid domain rule: {rule!r}")
        with self._lock:
            before = self.blocked_ips()
            self._rules.add(rule)
            return self.blocked_ips() - before

    def remove_rule(self, rule: str) -> set[str]:
        """Remove a rule; returns IPs that no remaining rule needs (to unblock)."""
        rule = normalize(rule)
        with self._lock:
            before = self.blocked_ips()
            self._rules.discard(rule)
            return before - self.blocked_ips()

    def domains(self) -> dict[str, list[str]]:
        with self._lock:
            return {d: sorted(ips) for d, ips in self._ips_by_domain.items()}
