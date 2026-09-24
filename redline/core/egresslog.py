"""Egress-log analyzer: find shadow AI across an environment from the traffic it makes.

The code inventory sees only declared AI in files. This sees AI in USE. Point it at
DNS, proxy, or firewall logs and it flags every hostname that belongs to a known AI
provider or looks like an MCP endpoint, tallies who called it and how often, then
diffs against a code inventory: providers seen on the wire but absent from the code
are shadow AI. Local and file-based, no network, no dependencies.

Recognizes, per line, a hostname from a range of formats without needing to be told
which: Squid/proxy access logs, Common/Combined web logs, CSV/TSV exports, dnsmasq
and BIND query logs, Zeek/JSON DNS, and bare host-per-line lists. Anything with a
hostname in it works; unknown lines are skipped.
"""
from __future__ import annotations

import ipaddress
import json
import re

# Known AI providers, matched by hostname suffix -> canonical provider name.
AI_HOST_SUFFIXES = {
    "api.openai.com": "OpenAI", "openai.com": "OpenAI", "oaistatic.com": "OpenAI",
    "chatgpt.com": "OpenAI (ChatGPT)", "chat.openai.com": "OpenAI (ChatGPT)",
    "api.anthropic.com": "Anthropic", "anthropic.com": "Anthropic",
    "claude.ai": "Anthropic (Claude)",
    "generativelanguage.googleapis.com": "Google Gemini",
    "aiplatform.googleapis.com": "Google Vertex AI", "gemini.google.com": "Google Gemini",
    "api.mistral.ai": "Mistral", "api.cohere.ai": "Cohere", "api.cohere.com": "Cohere",
    "api.groq.com": "Groq", "api.together.xyz": "Together AI", "api.together.ai": "Together AI",
    "api.replicate.com": "Replicate", "api.perplexity.ai": "Perplexity",
    "api.deepseek.com": "DeepSeek", "api.x.ai": "xAI",
    "huggingface.co": "Hugging Face", "api-inference.huggingface.co": "Hugging Face",
    "openrouter.ai": "OpenRouter", "api.fireworks.ai": "Fireworks",
    "api.anyscale.com": "Anyscale", "api.endpoints.anyscale.com": "Anyscale",
    "openai.azure.com": "Azure OpenAI",
    "cognitiveservices.azure.com": "Azure OpenAI", "githubcopilot.com": "GitHub Copilot",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot", "ollama.com": "Ollama (cloud)",
    "api.langchain.com": "LangChain", "smith.langchain.com": "LangSmith",
    "poe.com": "Poe", "character.ai": "Character.AI", "pi.ai": "Inflection",
}
# a few provider tokens appear as a LABEL, not a suffix (e.g.
# bedrock-runtime.us-east-1.amazonaws.com); match those as an infix.
_INFIX_HOSTS = {"bedrock-runtime": "AWS Bedrock"}

# canonical provider key, so the egress vocabulary and the inventory vocabulary
# correlate exactly instead of by fragile substring. Ordered: first hint wins.
_KEY_HINTS = [
    ("azure-openai", ("azure",)),
    ("openai", ("openai", "chatgpt")),
    ("anthropic", ("anthropic", "claude")),
    ("google", ("gemini", "vertex", "google")),
    ("aws", ("bedrock", "aws")),
    ("mistral", ("mistral",)), ("cohere", ("cohere",)), ("groq", ("groq",)),
    ("together", ("together",)), ("replicate", ("replicate",)),
    ("perplexity", ("perplexity",)), ("deepseek", ("deepseek",)), ("xai", ("xai", "x.ai")),
    ("huggingface", ("hugging", "huggingface")), ("openrouter", ("openrouter",)),
    ("fireworks", ("fireworks",)), ("anyscale", ("anyscale",)),
    ("copilot", ("copilot",)), ("ollama", ("ollama",)),
    ("langsmith", ("langsmith",)), ("langchain", ("langchain",)),
    ("poe", ("poe",)), ("characterai", ("character.ai", "character ai", "characterai")),
    ("inflection", ("inflection", "pi.ai")),
]


def provider_key(name: str) -> str:
    """Map any provider display name (egress or inventory) to a canonical key."""
    n = (name or "").lower()
    for key, hints in _KEY_HINTS:
        if any(h in n for h in hints):
            return key
    return n.split(" (")[0].strip()


# substrings that flag a plausible MCP endpoint in a path or hostname
_MCP_HINT = re.compile(r"(/mcp\b|/sse\b|mcp[.-]|model[-.]?context)", re.I)

# hostname token: a dotted name, optionally with a :port
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.\-]{1,253}\.[a-z]{2,})(?::\d+)?\b", re.I)
_URL_RE = re.compile(r"https?://([a-z0-9][a-z0-9.\-]{1,253}\.[a-z]{2,})(?::\d+)?(/[^\s\"']*)?", re.I)


def classify_host(host: str) -> tuple[str | None, str]:
    """Return (provider_name_or_None, kind). kind in {provider, mcp, other}.

    Matches a provider only as an exact host or a real dotted suffix (so
    api.openai.com.evil.net and api.airbnb.ai are NOT OpenAI/Inflection), preferring
    the most specific suffix (chat.openai.com -> ChatGPT, not the generic OpenAI)."""
    h = (host or "").lower().strip().rstrip(".")
    best = None
    for suffix, name in AI_HOST_SUFFIXES.items():
        if h == suffix or h.endswith("." + suffix):
            if best is None or len(suffix) > len(best[0]):
                best = (suffix, name)
    if best:
        return best[1], "provider"
    for token, name in _INFIX_HOSTS.items():
        if token in h:
            return name, "provider"
    if _MCP_HINT.search(h):
        return None, "mcp"
    return None, "other"


def _extract(line: str) -> tuple[str | None, str | None, str | None]:
    """Pull (host, path, actor) out of one log line across common formats."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None, None
    # JSON line (Zeek/DNS/structured): look for common host + client fields
    if line[:1] in "{[":
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            host = (obj.get("query") or obj.get("host") or obj.get("server_name")
                    or obj.get("dns.query") or obj.get("url") or obj.get("domain"))
            actor = (obj.get("id.orig_h") or obj.get("src") or obj.get("client")
                     or obj.get("clientip") or obj.get("source_ip") or obj.get("user"))
            if host:
                m = _URL_RE.match(str(host))
                if m:
                    return m.group(1), m.group(2), actor
                return str(host).rstrip("."), None, actor
    # URL anywhere in the line (proxy/combined logs)
    m = _URL_RE.search(line)
    if m:
        return m.group(1), m.group(2), _leading_ip(line)
    # CONNECT host:port (Squid HTTPS)
    m = re.search(r"CONNECT\s+([a-z0-9][a-z0-9.\-]+):\d+", line, re.I)
    if m:
        return m.group(1), None, _leading_ip(line)
    # dnsmasq / BIND "query[A] host.name from 10.0.0.5"
    m = re.search(r"query(?:\[[A-Z]+\])?[: ]+([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})", line, re.I)
    if m:
        actor = None
        fm = re.search(r"from ([0-9a-f:.]+)", line, re.I)
        if fm:
            actor = fm.group(1)
        return m.group(1), None, actor
    # bare hostname per line, or CSV/TSV with a hostname column
    for tok in re.split(r"[\s,;\t]+", line):
        m = _HOST_RE.fullmatch(tok)
        if m:
            return m.group(1), None, _leading_ip(line)
    return None, None, _leading_ip(line)


def _leading_ip(line: str):
    m = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]+)", line)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            return m.group(1)
        except ValueError:
            return None
    return None


def analyze_lines(lines) -> dict:
    """Tally AI-provider and MCP hosts seen in the log lines."""
    providers: dict[str, dict] = {}
    mcp: dict[str, dict] = {}
    total = matched = 0
    for line in lines:
        total += 1
        host, path, actor = _extract(line)
        if not host:
            continue
        name, kind = classify_host(host)
        if kind == "other" and not (path and _MCP_HINT.search(path)):
            continue
        matched += 1
        if kind == "mcp" or (path and _MCP_HINT.search(path)):
            e = mcp.setdefault(host, {"hits": 0, "actors": set(), "paths": set()})
            e["hits"] += 1
            if actor:
                e["actors"].add(actor)
            if path:
                e["paths"].add(path.split("?")[0][:80])
        else:
            e = providers.setdefault(name, {"hits": 0, "hosts": set(), "actors": set()})
            e["hits"] += 1
            e["hosts"].add(host)
            if actor:
                e["actors"].add(actor)
    return {
        "lines_read": total,
        "ai_hits": matched,
        "providers": {n: {"hits": v["hits"], "hosts": sorted(v["hosts"]),
                          "actors": sorted(v["actors"])[:50], "actor_count": len(v["actors"])}
                      for n, v in sorted(providers.items())},
        "mcp_endpoints": {h: {"hits": v["hits"], "actors": sorted(v["actors"])[:50],
                             "paths": sorted(v["paths"])}
                          for h, v in sorted(mcp.items())},
    }


def analyze_file(path: str) -> dict:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return analyze_lines(f)


def shadow_delta(egress: dict, inventory: dict | None) -> dict:
    """Diff providers seen on the wire against providers declared in a code inventory,
    correlating on canonical provider keys (not fragile substring matching). Providers
    in traffic but not in code are shadow AI."""
    seen = list(egress.get("providers", {}))
    seen_by_key = {provider_key(n): n for n in seen}
    declared_raw = []
    if inventory:
        declared_raw = list(inventory.get("summary", {}).get("providers", [])) \
            + list(inventory.get("summary", {}).get("frameworks", []))
    declared_raw = [d for d in declared_raw if d and d.strip()]
    declared_keys = {provider_key(d) for d in declared_raw}

    shadow = sorted(name for key, name in seen_by_key.items() if key not in declared_keys)
    corroborated = sorted(name for key, name in seen_by_key.items() if key in declared_keys)
    declared_unused = sorted(d for d in declared_raw if provider_key(d) not in seen_by_key)
    return {
        "shadow_ai_providers": shadow,        # on the wire, absent from code
        "corroborated_providers": corroborated,  # in both
        "declared_not_observed": declared_unused,  # in code, no traffic seen
        "mcp_endpoints_in_traffic": sorted(egress.get("mcp_endpoints", {})),
        "verdict": ("shadow AI found" if shadow or egress.get("mcp_endpoints")
                    else "no undeclared AI traffic in these logs"),
    }
