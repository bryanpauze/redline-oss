"""Compare a scan against a previous one, so CI can fail on *new* findings only.

A team that already knows about three findings (and has tickets for them) doesn't
want every build to go red. Diffing against a stored baseline surfaces what
changed: new findings, fixed findings, and ones still open.
"""
from __future__ import annotations

import json


def _vuln_ids(scan: dict) -> set[str]:
    return {r["id"] for r in scan.get("results", []) if r.get("vulnerable")}


def load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def diff(current: dict, baseline: dict) -> dict:
    cur, base = _vuln_ids(current), _vuln_ids(baseline)
    return {
        "new": sorted(cur - base),
        "fixed": sorted(base - cur),
        "still_open": sorted(cur & base),
        "baseline_target": baseline.get("target"),
        "baseline_started": baseline.get("started"),
    }


def should_fail(current: dict, fail_on: str, delta: dict | None) -> bool:
    """fail_on: 'any' (any finding), 'new' (only findings absent from baseline), 'none'."""
    if fail_on == "none":
        return False
    if fail_on == "new":
        return bool(delta["new"]) if delta is not None else bool(_vuln_ids(current))
    return bool(_vuln_ids(current))
