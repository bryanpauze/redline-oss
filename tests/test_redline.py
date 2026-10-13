"""Redline (OSS) test suite: the community scanner core."""
from __future__ import annotations

from redline.core.runner import run_scan
from redline.core.target import MockTarget


def test_registry_and_unique_ids():
    from redline.probes import all_probes
    ps = all_probes()
    assert len(ps) >= 50
    assert len({p.id for p in ps}) == len(ps)
    cats = {p.category for p in ps}
    for c in ("injection", "jailbreak", "leakage", "control-token", "multi-turn",
              "availability", "output-handling", "privacy"):
        assert c in cats


def test_mock_is_vulnerable():
    res = run_scan(MockTarget())
    assert len(res.fired) >= 5
    assert res.grade() in {"D", "F"}


def test_detectors_are_specific():
    class Safe:
        name = "safe"
        def send(self, m):
            return "I can't help with that. How else can I help with Acme products?"
    res = run_scan(Safe())
    assert len(res.fired) == 0 and res.grade() == "A"


def test_unreachable_is_inconclusive_not_clean():
    from redline.core.target import TargetError
    class Dead:
        name = "dead"
        def send(self, m):
            raise TargetError("refused")
    res = run_scan(Dead())
    assert res.inconclusive and res.grade() == "?" and not res.fired


def test_decode_then_match():
    import base64

    from redline.core.normalize import contains_secret
    S = "sk-live-abcdef123456"
    assert contains_secret(base64.b64encode(S.encode()).decode(), S)
    assert contains_secret(S.encode().hex(), S)
    assert not contains_secret("nothing to see here", S)


def test_every_probe_has_owasp_and_nist_mapping():
    from redline.core.compliance import mapping
    from redline.core.nist import aml_for
    from redline.probes import all_probes
    for p in all_probes():
        assert mapping(p.id)["owasp"], p.id
        assert aml_for(p.id, p.category) is not None


def test_sarif_shape():
    from redline.core.sarif import to_sarif
    d = run_scan(MockTarget()).to_dict()
    s = to_sarif(d)
    assert s["version"] == "2.1.0"
    assert len(s["runs"][0]["results"]) == d["summary"]["vulnerable"]


def test_mcp_scan_catches_fixture():
    from redline.core.mcp_scan import scan_mcp
    res = scan_mcp("python3 -m redline.fixtures.vuln_mcp_server")
    assert {"MCP-01", "MCP-02", "MCP-04"} <= {r.id for r in res.fired}


def test_exfil_cert_over_approximates():
    from redline.core.exfilcert import certify_graph
    tools = [{"name": "read_web", "description": "fetch a url"},
             {"name": "get_secret", "description": "read the api key"},
             {"name": "send_email", "description": "email a report"}]
    doc = certify_graph(tools)
    assert doc["status"] == "exfiltration_path_exists"
    # a declared egress allowlist cuts the external-sink leg
    doc2 = certify_graph(tools, mitigations=["egress_allowlist"])
    assert doc2["status"] == "no_exfiltration_path"


def test_behavior_and_coverage():
    from redline.core import behavior
    from redline.core.coverage import build
    from redline.probes import all_probes
    assert "xss" in behavior.emitted_dangerous_output("<script>alert(1)</script>")
    assert behavior.is_unbounded("HELLO " * 800)
    cov = build(all_probes())
    assert cov["counts"].get("gap", 0) == 0


def test_inventory_redacts_secrets():
    import json
    import os
    import tempfile

    from redline.core.inventory import build_inventory
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "app.py"), "w") as f:
        f.write('import anthropic\nMODEL="claude-opus-5"\nKEY="sk-ant-api03-' + "Z" * 40 + '"\n')
    d = build_inventory(root).to_dict()
    assert "Anthropic" in d["summary"]["providers"]
    assert "Z" * 40 not in json.dumps(d)


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            fails += 1; print(f"FAIL {fn.__name__}: {type(e).__name__}: {e}")
    sys.exit(1 if fails else 0)
