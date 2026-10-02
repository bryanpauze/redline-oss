"""`inventory`, `egress-scan`, `coverage`: discovery and reporting commands."""
from __future__ import annotations

import json

from ..shared import write_json


def cmd_inventory(a) -> int:
    from ...core.inventory import build_inventory, to_cyclonedx
    d = build_inventory(a.path).to_dict()
    sm = d["summary"]
    if a.json:
        write_json(a.json, d)
    if a.cyclonedx:
        write_json(a.cyclonedx, to_cyclonedx(d))
    print(f"\n  AI inventory of {d['root']}  ({sm['files_scanned']} files)")
    print(f"  Providers : {', '.join(sm['providers']) or '-'}")
    print(f"  Models    : {', '.join(m['id'] for m in d['models'][:12]) or '-'}")
    print(f"  MCP servers: {', '.join(s['name'] for s in d['mcp_servers']) or '-'}")
    for f in d["findings"]:
        print(f"    [{f['severity']:8}] {f['title']}  ({f['location']})")
    order = ["critical", "high", "medium", "low"]
    if a.fail_on == "none":
        return 0
    return 1 if any(order.index(f["severity"]) <= order.index(a.fail_on)
                    for f in d["findings"]) else 0


def cmd_egress_scan(a) -> int:
    from ...core.egresslog import analyze_lines, shadow_delta
    lines = []
    for path in a.logs:
        with open(path, errors="ignore") as f:
            lines += f.read().splitlines()
    egress = analyze_lines(lines)
    inv = None
    if a.inventory:
        with open(a.inventory) as f:
            inv = json.load(f)
    delta = shadow_delta(egress, inv)
    print(f"\n  Providers on the wire: {', '.join(egress.get('providers', {})) or '-'}")
    print(f"  Shadow AI (seen but not in code): {', '.join(delta['shadow']) or 'none'}")
    return 1 if (a.fail_on_shadow and delta["shadow"]) else 0


def cmd_coverage(a) -> int:
    from ...core import coverage as cov_mod
    from ...probes import all_probes
    c = cov_mod.build(all_probes())
    print(cov_mod.render_text(c))
    if a.out:
        with open(a.out, "w") as f:
            f.write(cov_mod.render_markdown(c))
        print(f"\n  Markdown: {a.out}")
    if a.json:
        write_json(a.json, c)
    return 0


def register(sub) -> None:
    inv = sub.add_parser("inventory", help="AI-BOM: models, SDKs, MCP servers, prompts, secrets")
    inv.add_argument("path", nargs="?", default=".")
    inv.add_argument("--json", default=None)
    inv.add_argument("--cyclonedx", default=None)
    inv.add_argument("--fail-on", choices=["none", "critical", "high"], default="none")
    inv.set_defaults(func=cmd_inventory)

    el = sub.add_parser("egress-scan", help="find shadow AI in DNS/proxy/firewall logs")
    el.add_argument("logs", nargs="+")
    el.add_argument("--inventory", default=None)
    el.add_argument("--fail-on-shadow", action="store_true")
    el.set_defaults(func=cmd_egress_scan)

    cov = sub.add_parser("coverage", help="NIST AI 100-2e adversarial-ML coverage matrix")
    cov.add_argument("--out", default=None)
    cov.add_argument("--json", default=None)
    cov.set_defaults(func=cmd_coverage)
