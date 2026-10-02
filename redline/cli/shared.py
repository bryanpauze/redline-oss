"""Shared CLI helpers: target construction, the common argument group, and small
I/O utilities. Used by more than one command module; nothing here prints a summary
or decides an exit code -- that belongs to the individual commands."""
from __future__ import annotations

import argparse
import json
import os
import sys

from ..core.target import AnthropicTarget, MockTarget, OllamaTarget, OpenAICompatTarget

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPEN_WEIGHT_TARGETS = ["vllm", "llamacpp", "tgi", "lmstudio", "together", "groq",
                       "openrouter", "fireworks", "deepinfra", "completion"]
TARGET_CHOICES = ["mock", "guarded", "ollama", "openai", "anthropic", "http",
                  "mcp", *OPEN_WEIGHT_TARGETS]
TEMPLATE_CHOICES = ["chatml", "llama3", "alpaca", "mistral", "plain"]


def temperature(a):
    if a.temperature is not None:
        return a.temperature
    return 0.0 if a.trials <= 1 else 0.7


def build_target(a):
    t = temperature(a)
    if a.target == "mock":
        return MockTarget()
    if a.target == "guarded":
        from ..core.target import GuardedMockTarget
        return GuardedMockTarget()
    if a.target == "ollama":
        return OllamaTarget(model=a.model or "llama3.1:8b", host=a.host, temperature=t)
    if a.target == "openai":
        return OpenAICompatTarget(url=OPENAI_URL, model=a.model or "gpt-4o-mini",
                                  api_key=a.api_key or os.environ.get("OPENAI_API_KEY"),
                                  temperature=t)
    if a.target == "anthropic":
        return AnthropicTarget(model=a.model or "claude-opus-5", api_key=a.api_key)
    if a.target == "http":
        if not a.url:
            sys.exit("error: --url is required for --target http")
        return OpenAICompatTarget(url=a.url, model=a.model or "default",
                                  api_key=a.api_key or os.environ.get("REDLINE_TARGET_API_KEY"),
                                  temperature=t)
    from ..core.target import OPENAI_COMPAT_PRESETS
    if a.target in OPENAI_COMPAT_PRESETS:
        from ..core.target import preset_target
        _u, env = OPENAI_COMPAT_PRESETS[a.target]
        key = a.api_key or os.environ.get(env) or os.environ.get("REDLINE_TARGET_API_KEY")
        host = a.url or (a.host if getattr(a, "host", None)
                         and a.host != "http://localhost:11434" else None)
        return preset_target(a.target, model=a.model or "default", api_key=key,
                             host=host, temperature=t)
    if a.target == "completion":
        from ..core.target import TextCompletionTarget
        return TextCompletionTarget(url=a.url or "http://localhost:8080/completion",
                                    model=a.model or "default",
                                    api_key=a.api_key or os.environ.get("REDLINE_TARGET_API_KEY"),
                                    template=getattr(a, "template", "chatml"), temperature=t)
    sys.exit(f"unknown target: {a.target}")


def progress(i, n, p):
    print(f"  [{i}/{n}] {p.id} {p.title}...", file=sys.stderr)


def write_json(path, obj) -> None:
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def add_target_args(s: argparse.ArgumentParser) -> None:
    """The common --target/--model/... block shared by scan, covert, fingerprint."""
    s.add_argument("--target", default="mock", choices=TARGET_CHOICES)
    s.add_argument("--model", default=None)
    s.add_argument("--host", default="http://localhost:11434")
    s.add_argument("--url", default=None)
    s.add_argument("--template", default="chatml", choices=TEMPLATE_CHOICES)
    s.add_argument("--api-key", default=None)
    s.add_argument("--temperature", type=float, default=None)
    s.add_argument("--command", default=None, help="launch command for --target mcp")
