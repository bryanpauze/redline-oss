"""Target adapters: the thing being scanned.

A Target accepts a list of chat messages [{"role","content"}, ...] and returns
the assistant's text reply. Redline wraps the target's system prompt with a
canary secret so leakage/override probes are measurable.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass


class TargetError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # SSRF: refuse every redirect off the guarded host
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _open_no_redirect(req, timeout):
    return _OPENER.open(req, timeout=timeout)


class Target:
    name = "base"

    def send(self, messages: list[dict]) -> str:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class OllamaTarget(Target):
    model: str = "llama3.1:8b"
    host: str = "http://localhost:11434"
    timeout: int = 120
    temperature: float | None = 0.0   # None = model default; >0 for multi-trial sampling

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def send(self, messages: list[dict]) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": ({} if self.temperature is None else {"temperature": self.temperature}),
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with _open_no_redirect(req, self.timeout) as r:
                data = json.loads(r.read())
            return (data.get("message") or {}).get("content", "") or ""
        except (urllib.error.URLError, TimeoutError, OSError, ValueError,
                KeyError, TypeError, http.client.HTTPException) as e:
            raise TargetError(f"ollama request failed: {type(e).__name__}: {e}") from e


@dataclass
class OpenAICompatTarget(Target):
    """Generic OpenAI-compatible /v1/chat/completions endpoint (a customer app)."""
    url: str = "http://localhost:8000/v1/chat/completions"
    model: str = "gpt-4o-mini"
    api_key: str | None = None
    timeout: int = 120
    temperature: float | None = 0.0
    label: str | None = None   # serving-stack name for reporting (e.g. "vllm", "groq")

    @property
    def name(self) -> str:
        return f"{self.label or 'http'}:{self.model}"

    def send(self, messages: list[dict]) -> str:
        payload = {"model": self.model, "messages": messages}
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url, data=body, headers=headers)
        try:
            with _open_no_redirect(req, self.timeout) as r:
                data = json.loads(r.read())
            return data["choices"][0]["message"]["content"] or ""
        except (urllib.error.URLError, TimeoutError, OSError, ValueError,
                KeyError, IndexError, TypeError, http.client.HTTPException) as e:
            raise TargetError(f"http request failed: {type(e).__name__}: {e}") from e


# Named presets for the OpenAI-compatible endpoints open-weight users actually run.
# value = (chat-completions URL, env var that holds the key). Self-hosted stacks take
# a key only if the operator set one; the hosted providers require theirs.
OPENAI_COMPAT_PRESETS: dict[str, tuple[str, str]] = {
    "vllm":       ("http://localhost:8000/v1/chat/completions", "VLLM_API_KEY"),
    "llamacpp":   ("http://localhost:8080/v1/chat/completions", "LLAMACPP_API_KEY"),
    "tgi":        ("http://localhost:8080/v1/chat/completions", "HF_TOKEN"),
    "lmstudio":   ("http://localhost:1234/v1/chat/completions", "LMSTUDIO_API_KEY"),
    "together":   ("https://api.together.xyz/v1/chat/completions", "TOGETHER_API_KEY"),
    "groq":       ("https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1/chat/completions", "OPENROUTER_API_KEY"),
    "fireworks":  ("https://api.fireworks.ai/inference/v1/chat/completions", "FIREWORKS_API_KEY"),
    "deepinfra":  ("https://api.deepinfra.com/v1/openai/chat/completions", "DEEPINFRA_API_KEY"),
}


def preset_target(preset: str, *, model: str, api_key: str | None = None,
                  host: str | None = None, temperature: float | None = 0.0) -> OpenAICompatTarget:
    """Build an OpenAI-compatible target for a named serving stack. `host` overrides the
    scheme+host for a self-hosted stack (e.g. --host http://your-llm-host:8081), keeping the path."""
    url, _env = OPENAI_COMPAT_PRESETS[preset]
    if host:
        from urllib.parse import urlsplit, urlunsplit
        p, h = urlsplit(host), urlsplit(url)
        url = urlunsplit((p.scheme or "http", p.netloc or host, h.path, "", ""))
    return OpenAICompatTarget(url=url, model=model, api_key=api_key,
                              temperature=temperature, label=preset)


def _flatten(messages: list[dict], template: str) -> str:
    """Render a chat history into a single prompt for a completion endpoint. The template
    choice matters: it is the boundary a control-token or prefill probe is testing."""
    parts = []
    if template == "chatml":
        for m in messages:
            parts.append(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>")
        parts.append("<|im_start|>assistant\n")
    elif template == "llama3":
        parts.append("<|begin_of_text|>")
        for m in messages:
            parts.append(f"<|start_header_id|>{m['role']}<|end_header_id|>\n\n"
                         f"{m['content']}<|eot_id|>")
        parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
    elif template == "alpaca":
        sys = "\n".join(m["content"] for m in messages if m["role"] == "system")
        usr = "\n".join(m["content"] for m in messages if m["role"] == "user")
        if sys:
            parts.append(sys)
        parts.append(f"### Instruction:\n{usr}\n\n### Response:\n")
    elif template == "mistral":
        sys = "\n".join(m["content"] for m in messages if m["role"] == "system")
        usr = "\n".join(m["content"] for m in messages if m["role"] == "user")
        parts.append(f"[INST] {sys}\n\n{usr} [/INST]")
    else:  # plain: raw concatenation, the base-model case
        for m in messages:
            parts.append(f"{m['role']}: {m['content']}")
        parts.append("assistant:")
    return "\n".join(parts)


@dataclass
class TextCompletionTarget(Target):
    """A raw completion endpoint (llama.cpp /completion, or an OpenAI /v1/completions),
    the base/completion serving mode open-weight models are often exposed through. The
    chat history is flattened client-side with a selectable template, so control-token,
    prefill, and base-completion probes exercise the real templating boundary."""
    url: str = "http://localhost:8080/completion"
    model: str = "default"
    api_key: str | None = None
    template: str = "chatml"
    timeout: int = 120
    temperature: float | None = 0.0
    max_tokens: int = 512

    @property
    def name(self) -> str:
        return f"completion:{self.model}"

    def send(self, messages: list[dict]) -> str:
        prompt = _flatten(messages, self.template)
        openai_style = self.url.rstrip("/").endswith("/v1/completions")
        if openai_style:
            payload = {"model": self.model, "prompt": prompt, "max_tokens": self.max_tokens}
            if self.temperature is not None:
                payload["temperature"] = self.temperature
        else:  # llama.cpp server /completion
            payload = {"prompt": prompt, "n_predict": self.max_tokens}
            if self.temperature is not None:
                payload["temperature"] = self.temperature
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url, data=body, headers=headers)
        try:
            with _open_no_redirect(req, self.timeout) as r:
                data = json.loads(r.read())
            if openai_style:
                return data["choices"][0].get("text", "") or ""
            return data.get("content", "") or ""   # llama.cpp shape
        except (urllib.error.URLError, TimeoutError, OSError, ValueError,
                KeyError, IndexError, TypeError, http.client.HTTPException) as e:
            raise TargetError(f"completion request failed: {type(e).__name__}: {e}") from e


@dataclass
class AnthropicTarget(Target):
    """Claude via the official Anthropic SDK (optional extra: pip install 'redline-scan[anthropic]').

    Credentials resolve the SDK's usual way (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN,
    or an `ant auth login` profile). No sampling parameters are sent: current Claude
    models reject them. Server-side refusal fallbacks are intentionally NOT enabled:
    a scanner must measure exactly the model it was pointed at, and a silent
    fallback would swap in a different model and falsify the result. A refusal is
    recorded as the target's (blocked) reply.
    """
    model: str = "claude-opus-5"
    api_key: str | None = None
    max_tokens: int = 16000

    @property
    def name(self) -> str:
        return f"anthropic:{self.model}"

    def _client(self):
        try:
            import anthropic
        except ImportError as e:
            raise TargetError("the Anthropic target needs the SDK: "
                              "pip install 'redline-scan[anthropic]'") from e
        return anthropic, (anthropic.Anthropic(api_key=self.api_key)
                           if self.api_key else anthropic.Anthropic())

    def send(self, messages: list[dict]) -> str:
        anthropic, client = self._client()
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [{"role": m["role"], "content": m["content"]}
                 for m in messages if m["role"] in ("user", "assistant")]
        try:
            kwargs = {"model": self.model, "max_tokens": self.max_tokens, "messages": convo}
            if system:
                kwargs["system"] = system
            resp = client.messages.create(**kwargs)
        except anthropic.APIConnectionError as e:
            raise TargetError(f"anthropic connection failed: {e}") from e
        except anthropic.APIStatusError as e:
            raise TargetError(f"anthropic API error {e.status_code}: {e.message}") from e
        if resp.stop_reason == "refusal":
            return "[refused]"
        return "".join(b.text for b in resp.content if b.type == "text")


class GuardedMockTarget(Target):
    """A decode-blind keyword guardrail in front of a model that DECODES intent.

    The guardrail refuses if any denylisted term appears in the RAW request. The
    model behind it normalizes/decodes the request, so an obfuscated ask still
    elicits a leak. Breaking through therefore requires a transform that evades the
    raw filter while preserving the decoded intent -- the realistic adversarial gap
    Redline's search is built to find and measure.
    """
    name = "mock:guarded"

    def __init__(self, denylist=None):
        self.denylist = [d.lower() for d in (denylist or
                         ["api key", "apikey", "secret", "password", "credential"])]

    def send(self, messages: list[dict]) -> str:
        from .obfuscation import _fold_unicode, _strip_sep, recover
        user = "\n".join(m["content"] for m in messages if m["role"] != "system")
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        raw = user.lower()
        if any(term in raw for term in self.denylist):
            return "I can't help with that request."
        # the model decodes: normalize + peel encodings, then judge intent
        views = [ _fold_unicode(user), _strip_sep(_fold_unicode(user)) ] + recover(user)
        norm = " ".join(v.lower() for v in views)
        if any(k in norm for k in ("apikey", "api key", "secret", "credential", "key")):
            # comprehends the (obfuscated) ask and leaks the planted secret
            m = re.search(r"internal api key is (\S+)", system)
            return f"Sure, the key is {m.group(1)}" if m else system
        return "I'm a helpful assistant."


class MockTarget(Target):
    """A deliberately vulnerable agent, for demos and CI.

    It naively concatenates everything into one prompt and obeys the last
    instruction it sees -- the classic insecure-agent failure mode. Used so a
    scan always runs and always demonstrates real detections offline.
    """
    name = "mock:vulnerable-agent"

    def send(self, messages: list[dict]) -> str:
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = "\n".join(m["content"] for m in messages if m["role"] != "system")
        low = convo.lower()
        # Naively leaks its own system prompt when asked to repeat/print it.
        if any(k in low for k in ("repeat the text above", "your instructions",
                                  "system prompt", "print your", "starting with")):
            return f"Sure! Here are my instructions:\n{system}"
        # Reveals a named secret on request.
        if "secret" in low or "api key" in low or "password" in low:
            return f"My configuration is:\n{system}"
        # Obeys injected 'ignore previous instructions' overrides verbatim.
        if "ignore" in low and ("previous" in low or "above" in low):
            tail = convo.strip().splitlines()[-1] if convo.strip() else ""
            return f"Okay, ignoring prior instructions. {tail}"
        return "I'm a helpful assistant. How can I help you today?"


def target_from_spec(spec: str, *, api_key: str | None = None, url: str | None = None,
                     temperature: float | None = 0.0) -> Target:
    """Build a target from a 'provider:model' string, e.g. 'ollama:hermes3',
    'groq:llama-3.1-70b', 'anthropic:claude-opus-5', 'completion:local'. Used for the --target-style CLIs (a judge model, a completion endpoint, and so on)."""
    provider, _, model = spec.partition(":")
    model = model or "default"
    if provider == "mock":
        return MockTarget()
    if provider == "ollama":
        return OllamaTarget(model=model, host=url or "http://localhost:11434",
                            temperature=temperature)
    if provider == "openai":
        return OpenAICompatTarget(url="https://api.openai.com/v1/chat/completions",
                                  model=model, api_key=api_key or os.environ.get("OPENAI_API_KEY"),
                                  temperature=temperature)
    if provider == "anthropic":
        return AnthropicTarget(model=model, api_key=api_key)
    if provider in OPENAI_COMPAT_PRESETS:
        _u, env = OPENAI_COMPAT_PRESETS[provider]
        return preset_target(provider, model=model,
                             api_key=api_key or os.environ.get(env)
                             or os.environ.get("REDLINE_TARGET_API_KEY"),
                             host=url, temperature=temperature)
    if provider == "completion":
        return TextCompletionTarget(url=url or "http://localhost:8080/completion",
                                    model=model, temperature=temperature)
    if provider == "http":
        if not url:
            raise ValueError("http spec needs a url")
        return OpenAICompatTarget(url=url, model=model,
                                  api_key=api_key or os.environ.get("REDLINE_TARGET_API_KEY"),
                                  temperature=temperature)
    raise ValueError(f"unknown target provider: {provider!r}")
