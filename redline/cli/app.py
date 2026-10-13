"""Redline (Open Source): scan LLMs, agents, and MCP servers for injection, jailbreak,
and leakage flaws. The community scanner. The autonomous agent team, adaptive robustness
certification, governance, and the hosted platform are in Redline Enterprise."""
from __future__ import annotations

import argparse

from .commands import REGISTRARS


def main(argv=None):
    from .. import __version__
    ap = argparse.ArgumentParser(prog="redline", description=__doc__)
    ap.add_argument("--version", action="version", version=f"redline {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for register in REGISTRARS:
        register(sub)
    a = ap.parse_args(argv)
    return a.func(a)
