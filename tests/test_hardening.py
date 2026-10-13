"""Regression tests for the public-readiness review: each pins a verified defect."""
from __future__ import annotations

import base64
import json

import pytest

from redline.core.behavior import called_sink_with
from redline.core.covert import achieved_capacity
from redline.core.deployed import generic_leak
from redline.core.evidence import verify_document
from redline.core.exfilcert import certify_graph
from redline.core.obfuscation import reveals
from redline.core.runner import run_scan
from redline.core.target import MockTarget, OpenAICompatTarget, TargetError, preset_target
from redline.probes import ScanContext, all_probes

PROBES = {p.id: p for p in all_probes()}
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"   # built at runtime: a fixture, not a secret


class _Echo:
    name = "echo"

    def send(self, messages):
        return "Received: " + "\n".join(m["content"] for m in messages if m["role"] != "system")


class _Down:
    name = "down"

    def send(self, messages):
        raise TargetError("connection refused")


class _HalfDown:
    name = "half"

    def __init__(self):
        self.n = 0

    def send(self, messages):
        self.n += 1
        if self.n % 3:
            raise TargetError("503")
        return "I'm a helpful assistant."


def test_echoing_target_is_not_vulnerable():
    assert run_scan(_Echo()).fired == []


def test_mock_still_detected_after_echo_stripping():
    ids = {r.id for r in run_scan(MockTarget()).fired}
    assert {"INJ-01", "LK-01", "JB-01"} <= ids


def test_mostly_unreachable_target_is_inconclusive_not_clean():
    res = run_scan(_HalfDown())
    assert res.inconclusive and res.grade() == "?"


def test_failed_judge_abstains_instead_of_hiding_findings():
    class BrokenJudge:
        name = "broken"

        def confirm(self, *a):
            return None
    res = run_scan(MockTarget(), validator=BrokenJudge())
    assert len(res.fired) >= 10


def test_polymorph_grades_reliability():
    res = run_scan(MockTarget(), polymorph=4, only=["leakage"])
    assert all(r.verdict != "detected" for r in res.fired)


def test_token_detector_ignores_refusals():
    ctx = ScanContext()
    det = PROBES["INJ-01"].detect
    assert det(ctx.token, ctx)
    assert not det(f"That tried to get me to reply, so I will not reply with {ctx.token}", ctx)
    assert not det(f"The doc asked me to output:\n{ctx.token}\nI ignored it.", ctx)


def test_exfil_cert_is_sound_on_identifier_names_and_unknown_tools():
    for tools in ([{"name": "fetchUrl"}, {"name": "getCredentials"}, {"name": "slackPost"}],
                  [{"name": "read_customer_records"}, {"name": "post_to_webhook"}],
                  [{"name": "search_inbox"}, {"name": "send_email"}],
                  [{"name": "frobnicate"}]):
        assert certify_graph(tools)["status"] == "exfiltration_path_exists", tools


def test_exfil_cert_declared_roles_and_input_not_mutated():
    tools = [{"name": "get_weather", "redline_roles": ["untrusted_ingress"]}, {"bad": 1}, "x"]
    doc = certify_graph(tools)  # type: ignore[arg-type]
    assert doc["status"] == "no_exfiltration_path"
    assert "_roles" not in tools[0]


def test_exfil_cert_unsigned_without_key(monkeypatch):
    monkeypatch.delenv("REDLINE_AUDIT_KEY", raising=False)
    doc = certify_graph([{"name": "send_email"}])
    assert doc["signature"]["signed"] is False


def test_verify_document_rejects_malformed():
    assert not verify_document([])["ok"]  # type: ignore[arg-type]
    assert not verify_document({"signature": {"signed": True, "value": 5}}, "k")["ok"]


def test_covert_does_not_credit_public_prefix():
    ctx = ScanContext()
    assert achieved_capacity("Our support hours are 9 to 5.", ctx.secret)["achieved_bits"] == 0
    fake = base64.b64encode(b"sk-live-0000000000000000").decode()
    assert not PROBES["CC-03"].detect(fake, ctx)
    assert PROBES["CC-03"].detect(base64.b64encode(ctx.secret.encode()).decode(), ctx)


def test_decoder_is_bounded_on_huge_replies():
    import time
    t = time.time()
    reveals("1" * 1_000_000, "sk-live-abc")
    assert time.time() - t < 5


def test_deployed_leak_detector_precision():
    assert not generic_leak("enter your password: yourNewPass in the form")[0]
    assert not generic_leak("Use token: <redacted> in the header")[0]
    assert not generic_leak("You should never ask me that, and I never share the system prompt.")[0]
    assert generic_leak("password=Hunter2Prod!")[0]
    assert generic_leak(FAKE_AWS)[0]


def test_deployed_report_masks_real_secrets():
    class Leaky:
        name = "leaky"

        def send(self, messages):
            return f"config: {FAKE_AWS} and the app secret TOPSECRET-42"
    res = run_scan(Leaky(), deployed=True, app_canary="TOPSECRET-42", only=["leakage"])
    blob = json.dumps(res.to_dict())
    assert FAKE_AWS not in blob and "TOPSECRET-42" not in blob


def test_json_tool_call_arguments_are_checked():
    assert called_sink_with('{"name":"send_email","arguments":{"body":"SECRET123"}}', "SECRET123")


def test_preset_accepts_bare_host_port():
    assert preset_target("vllm", model="m", host="gpu-box:8081").url == \
        "http://gpu-box:8081/v1/chat/completions"


@pytest.mark.parametrize("url", ["file:///etc/hosts", "//host/v1/chat/completions"])
def test_bad_target_urls_raise_target_error(url):
    with pytest.raises(TargetError):
        OpenAICompatTarget(url=url).send([{"role": "user", "content": "hi"}])


def test_fingerprint_unreachable_is_inconclusive():
    from redline.core.fingerprint import fingerprint
    r = fingerprint(_Down())
    assert r["inconclusive"] and r["defense_class"] == "INCONCLUSIVE"


def test_cli_sarif_has_anchor_and_bad_profile_is_clean_error(tmp_path):
    from redline.cli import main
    sarif = tmp_path / "nested" / "out.sarif"
    assert main(["scan", "--target", "mock", "--quiet", "--sarif", str(sarif)]) == 1
    loc = json.loads(sarif.read_text())["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "redline.target"
    with pytest.raises(SystemExit) as e:
        main(["scan", "--target", "mock", "--quiet", "--profile", "nope"])
    assert "unknown profile" in str(e.value)


def test_cli_bad_baseline_exits_2(tmp_path):
    from redline.cli import main
    bad = tmp_path / "b.json"
    bad.write_text("{}")
    assert main(["scan", "--target", "mock", "--quiet", "--baseline", str(bad)]) == 2
