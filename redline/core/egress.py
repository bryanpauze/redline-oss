"""Egress policy: a default-deny allowlist for where a scan is allowed to reach.

Ported in spirit from control-plane's control_plane/box/egress.py, kept stdlib-only.
The SaaS server uses this instead of a hand-rolled SSRF check: an operator (or a
per-tenant config) sets rules, and every scan target and every host a probe would
reach is checked against `decide(host, port)`. First matching rule wins; nothing
matches means DENY.

A rule matches one of:
  - an exact domain ("api.openai.com")
  - a wildcard ("*.openai.com", strict subdomain: matches a.openai.com, not openai.com)
  - a single IP ("203.0.113.4")
  - a CIDR ("203.0.113.0/24")
and optionally a set of allowed ports (empty = any port).

Redline layers one hard rule on top that an allowlist can't override in hosted
mode: a host that resolves to a private, loopback, link-local, CGNAT, or reserved
address is denied regardless, so an allowlist entry can't be tricked into pointing
at internal infrastructure. That resolve-and-check is `guard_resolved()`.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EgressRule:
    match: str                       # domain | *.domain | ip | cidr
    ports: tuple[int, ...] = ()      # empty = any port
    note: str = ""

    def matches(self, host: str, port: int | None) -> bool:
        if self.ports and port is not None and port not in self.ports:
            return False
        m = self.match
        host = (host or "").lower().rstrip(".")
        if m.startswith("*."):
            suffix = m[1:].lower()               # ".openai.com"
            return host.endswith(suffix) and host != suffix[1:]
        try:
            net = ipaddress.ip_network(m, strict=False)
            try:
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        except ValueError:
            return host == m.lower()


@dataclass
class EgressPolicy:
    rules: list[EgressRule] = field(default_factory=list)
    default_allow: bool = False      # default DENY
    expires_at: float | None = None

    def expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or time.time()) >= self.expires_at

    def decide(self, host: str, port: int | None = None) -> tuple[bool, str]:
        """Return (allowed, reason). First matching rule wins; else the default."""
        if self.expired():
            return (False, "egress policy expired")
        for i, r in enumerate(self.rules):
            if r.matches(host, port):
                return (True, f"rule[{i}] {r.match}" + (f" ({r.note})" if r.note else ""))
        if self.default_allow:
            return (True, "default allow")
        return (False, f"no rule allows {host}" + (f":{port}" if port else ""))

    def to_dict(self) -> dict:
        return {
            "default_allow": self.default_allow,
            "expires_at": self.expires_at,
            "rules": [{"match": r.match, "ports": list(r.ports), "note": r.note}
                      for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict) -> EgressPolicy:
        return cls(
            rules=[EgressRule(match=r["match"], ports=tuple(r.get("ports", [])),
                              note=r.get("note", "")) for r in d.get("rules", [])],
            default_allow=bool(d.get("default_allow", False)),
            expires_at=d.get("expires_at"),
        )


def validate_rule(match: str) -> str | None:
    """None if the rule string is well-formed, else an error message."""
    if not match or not isinstance(match, str):
        return "rule must be a non-empty string"
    if match.startswith("*."):
        rest = match[2:]
        return None if rest and "." in rest else "wildcard must be like *.example.com"
    try:
        ipaddress.ip_network(match, strict=False)
        return None
    except ValueError:
        pass
    if any(c in match for c in " /\t"):
        return f"not a valid domain, IP, or CIDR: {match}"
    return None


class EgressDenied(Exception):
    pass


def _is_internal(ip: ipaddress._BaseAddress) -> bool:
    if ip.version == 6 and getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return not ip.is_global


def guard_resolved(url_host: str, policy: EgressPolicy | None,
                   port: int | None = None) -> None:
    """Resolve `url_host` and apply the hard internal-address rule, then the
    policy. Raises EgressDenied on any failure. This is the SSRF chokepoint."""
    try:
        infos = socket.getaddrinfo(url_host, port)
    except (socket.gaierror, UnicodeError, ValueError, TypeError) as e:
        raise EgressDenied(f"cannot resolve host: {url_host} ({type(e).__name__})") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_internal(ip):
            raise EgressDenied(
                "target resolves to a private/internal address; hosted scans must "
                "target a publicly reachable endpoint (self-host to scan internal LLMs)")
    if policy is not None:
        allowed, reason = policy.decide(url_host, port)
        if not allowed:
            raise EgressDenied(f"egress policy: {reason}")
