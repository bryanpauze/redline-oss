"""`exfil-cert` and `verify-evidence`: lethal-trifecta certificate + verification."""
from __future__ import annotations

import json
import sys

from ..shared import write_json


def cmd_exfil_cert(a) -> int:
    from ...core.exfilcert import certify_graph, certify_mcp
    if a.tools:
        with open(a.tools) as f:
            tools = json.load(f)
        doc = certify_graph(tools, mitigations=a.mitigation)
    elif a.mcp_url:
        doc = certify_mcp(a.mcp_url, "http", mitigations=a.mitigation)
    elif a.mcp_command:
        doc = certify_mcp(a.mcp_command, "stdio", mitigations=a.mitigation)
    else:
        sys.exit("error: pass --tools, --mcp-command, or --mcp-url")
    print(f"\n  Exfiltration certificate for {doc['target']}  (signed)")
    print(f"  VERDICT: {doc['status'].upper()}\n  {doc['verdict']}")
    if a.out:
        write_json(a.out, doc)
    return 1 if doc["status"] == "exfiltration_path_exists" else 0


def cmd_verify_evidence(a) -> int:
    from ...core.evidence import verify_document
    with open(a.path) as f:
        r = verify_document(json.load(f))
    print(f"  {'VALID' if r['ok'] else 'INVALID'}: {r['reason']}")
    return 0 if r["ok"] else 1


def register(sub) -> None:
    xc = sub.add_parser("exfil-cert", help="prove (soundly) whether an agent's tool graph "
                                           "can exfiltrate the lethal trifecta")
    xc.add_argument("--mcp-command", default=None)
    xc.add_argument("--mcp-url", default=None)
    xc.add_argument("--tools", default=None, help="tool-list JSON instead of a live MCP server")
    xc.add_argument("--mitigation", action="append", default=[],
                    help="declared control: egress_allowlist, quarantine, human_approval_sinks, "
                         "no_untrusted_input, no_private_data")
    xc.add_argument("--out", default=None)
    xc.set_defaults(func=cmd_exfil_cert)

    ve = sub.add_parser("verify-evidence", help="verify a signed certificate or bundle")
    ve.add_argument("path")
    ve.set_defaults(func=cmd_verify_evidence)
