"""`covert` and `fingerprint`: attack-surface measurement against a target."""
from __future__ import annotations

import json
import sys

from ..shared import add_target_args, build_target


def cmd_covert(a) -> int:
    from ...core.covert import measure_covert
    r = measure_covert(build_target(a))
    print(json.dumps(r, indent=2) if not sys.stdout.isatty() else r.get("summary", r))
    return 0


def cmd_fingerprint(a) -> int:
    from ...core.fingerprint import fingerprint
    r = fingerprint(build_target(a))
    print(f"\n  Target: {r['target']}\n  Defense class: {r['defense_class']}\n  {r['reason']}")
    return 0


def register(sub) -> None:
    cv = sub.add_parser("covert", help="measure covert-channel exfiltration capacity")
    add_target_args(cv)
    cv.add_argument("--trials", type=int, default=1)
    cv.set_defaults(func=cmd_covert)

    fp = sub.add_parser("fingerprint", help="name a target's guardrail defense class")
    add_target_args(fp)
    fp.add_argument("--trials", type=int, default=1)
    fp.set_defaults(func=cmd_fingerprint)
