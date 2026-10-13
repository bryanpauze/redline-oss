"""CLI-level tests: build_judge provider handling and the egress-scan path.

Offline: judges are built but never called; egress-scan reads a temp log file.
Run directly:  python tests/test_cli.py
"""
from __future__ import annotations

import contextlib
import io
import os
import tempfile

from redline.cli import main
from redline.core.target import AnthropicTarget, OllamaTarget, OpenAICompatTarget
from redline.core.validator import LLMJudge, build_judge


def test_build_judge_none():
    assert build_judge(None) is None
    assert build_judge("") is None


def test_build_judge_ollama_keeps_full_model_tag():
    j = build_judge("ollama:llama3.1:8b")
    assert isinstance(j, LLMJudge) and isinstance(j.judge, OllamaTarget)
    assert j.judge.model == "llama3.1:8b"


def test_build_judge_http_shorthand():
    j = build_judge("http:http://localhost:9999/v1/chat/completions")
    assert isinstance(j.judge, OpenAICompatTarget)
    assert j.judge.url == "http://localhost:9999/v1/chat/completions"
    assert j.judge.model == "gpt-4o-mini"


def test_build_judge_openai_anthropic_preset_now_work():
    # these raised "unknown judge spec" before build_judge routed through target_from_spec
    assert isinstance(build_judge("openai:gpt-4o-mini").judge, OpenAICompatTarget)
    assert isinstance(build_judge("anthropic:claude-opus-5").judge, AnthropicTarget)
    assert isinstance(build_judge("groq:llama-3.1-70b").judge, OpenAICompatTarget)


def test_build_judge_unknown_raises():
    try:
        build_judge("nope:whatever")
    except ValueError:
        return
    raise AssertionError("expected ValueError for an unknown provider")


def _egress(argv):
    """Run `redline egress-scan ...` capturing stdout; return exit code."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return main(argv)


def test_egress_scan_runs_without_crashing():
    # regression: the handler used to read delta["shadow"], which does not exist
    # (shadow_delta returns shadow_ai_providers) -> KeyError on every invocation.
    fd, log = tempfile.mkstemp(suffix=".log")
    os.write(fd, b"1.2.3.4 - - api.openai.com GET /v1/chat\n1.2.3.4 - - example.com GET /\n")
    os.close(fd)
    try:
        assert _egress(["egress-scan", log]) == 0
        # a provider on the wire with no code inventory counts as shadow -> exit 1
        assert _egress(["egress-scan", log, "--fail-on-shadow"]) == 1
    finally:
        os.unlink(log)


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
