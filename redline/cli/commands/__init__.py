"""Command modules. Each exposes register(sub) which adds its subparser(s) and
binds a handler via set_defaults(func=...). REGISTRARS is applied in order, so
this list also defines the order commands appear in `redline --help`."""
from __future__ import annotations

from . import certs, classify, inventory, robustness, scan, suite

REGISTRARS = [
    scan.register,       # scan, benchmark
    suite.register,      # probes, profiles, golden
    robustness.register,  # covert, fingerprint
    certs.register,      # exfil-cert, verify-evidence
    inventory.register,  # inventory, egress-scan, coverage
    classify.register,   # shadow-text
]

__all__ = ["REGISTRARS"]
