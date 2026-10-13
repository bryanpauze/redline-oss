"""End-to-end CLI command coverage: drive each subcommand through main() offline
(mock targets, local temp files) and assert exit codes + report artifacts.

This exercises the command registry, shared target-building, _emit, and the HTML/
JSON/SARIF report renderers without contacting any model. Run directly:
    python tests/test_cli_commands.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile

from redline.cli import main


def _run(argv):
    """Run main(argv) capturing stdout; return (exit_code_or_exit_arg, stdout)."""
    buf = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf):
            code = main(argv)
    except SystemExit as e:
        code = e.code
    return code, buf.getvalue()


def test_scan_mock_fires_and_writes_all_report_formats():
    d = tempfile.mkdtemp()
    out, js, sarif = (os.path.join(d, f) for f in ("r.html", "r.json", "r.sarif"))
    code, _ = _run(["scan", "--target", "mock", "--quiet",
                    "--out", out, "--json", js, "--sarif", sarif])
    assert code == 1   # the deliberately-insecure mock must fire findings
    # the renderers actually produced well-formed artifacts
    assert os.path.getsize(out) > 0
    rep = json.load(open(js))
    assert rep["results"] and "grade" in rep
    sar = json.load(open(sarif))
    assert sar["runs"][0]["results"]


def test_scan_baseline_diff_path():
    d = tempfile.mkdtemp()
    base = os.path.join(d, "base.json")
    _run(["scan", "--target", "mock", "--quiet", "--json", base])
    code, out = _run(["scan", "--target", "mock", "--quiet", "--baseline", base])
    assert code in (0, 1) and "vs baseline" in out


def test_probes_profiles_golden():
    assert _run(["probes"])[0] == 0
    assert _run(["profiles"])[0] == 0
    assert _run(["golden"])[0] in (0, 1)   # pass/fail depending on detectors, but runs


def test_coverage_text_and_json():
    d = tempfile.mkdtemp()
    js = os.path.join(d, "cov.json")
    code, out = _run(["coverage", "--json", js])
    assert code == 0 and os.path.getsize(js) > 0


def test_covert_and_fingerprint_mock():
    assert _run(["covert", "--target", "mock"])[0] == 0
    code, out = _run(["fingerprint", "--target", "mock"])
    assert code == 0 and "Defense class" in out


def test_exfil_cert_trifecta_exits_1_and_writes():
    d = tempfile.mkdtemp()
    tools = os.path.join(d, "tools.json")
    with open(tools, "w") as f:
        json.dump([{"name": "fetch", "description": "read an untrusted web page"},
                   {"name": "vault", "description": "read the private api key"},
                   {"name": "post", "description": "send data to an external url"}], f)
    out = os.path.join(d, "cert.json")
    code, text = _run(["exfil-cert", "--tools", tools, "--out", out])
    assert code == 1 and "VERDICT" in text and os.path.getsize(out) > 0


def test_exfil_cert_requires_an_input():
    code, _ = _run(["exfil-cert"])
    assert isinstance(code, str) and "pass --tools" in code


def test_verify_evidence_rejects_unsigned():
    d = tempfile.mkdtemp()
    doc = os.path.join(d, "doc.json")
    with open(doc, "w") as f:
        json.dump({"target": "x", "signature": {"signed": False}}, f)
    code, out = _run(["verify-evidence", doc])
    assert code == 1 and "INVALID" in out


def test_shadow_text():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.txt")
    with open(p, "w") as f:
        f.write("As an AI language model, it is important to note that, furthermore, ...")
    code, out = _run(["shadow-text", p])
    assert code == 0 and "likelihood" in out


def test_inventory_of_the_package():
    d = tempfile.mkdtemp()
    js = os.path.join(d, "inv.json")
    code, out = _run(["inventory", "redline/core", "--json", js])
    assert code == 0 and "AI inventory" in out and os.path.getsize(js) > 0


def test_unknown_target_exits():
    code, _ = _run(["scan", "--target", "http", "--quiet"])   # http needs --url
    assert isinstance(code, str) and "url" in code.lower()


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
