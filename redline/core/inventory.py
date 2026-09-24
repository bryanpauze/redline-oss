"""AI-BOM: inventory the AI footprint of a codebase.

`redline inventory <path>` walks a repository and reports what AI it actually runs:
provider SDKs and agent frameworks, model IDs referenced in code, configured MCP
servers, prompt files, model weights and datasets, and hardcoded LLM credentials.
Each asset carries risk notes, and the whole inventory exports as CycloneDX 1.6
(which has first-class machine-learning-model and data component types).

Secrets are never printed in full: only a provider-identifying prefix survives.
"""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field

from .. import __version__

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache", "site-packages",
             ".next", "target", "vendor", ".idea", ".gradle", "coverage"}
MAX_TEXT_BYTES = 1_000_000
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java",
            ".kt", ".cs", ".php", ".rs", ".swift", ".scala", ".ipynb"}
CONFIG_EXT = {".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg"}
IGNORE_MARK = "redline: ignore"

# --- provider SDKs / frameworks (package name -> (kind, display)) ---
PACKAGES = {
    # providers
    "anthropic": ("provider", "Anthropic"), "@anthropic-ai/sdk": ("provider", "Anthropic"),
    "openai": ("provider", "OpenAI"), "google-generativeai": ("provider", "Google Gemini"),
    "google-genai": ("provider", "Google Gemini"), "@google/generative-ai": ("provider", "Google Gemini"),
    "@google/genai": ("provider", "Google Gemini"), "mistralai": ("provider", "Mistral"),
    "@mistralai/mistralai": ("provider", "Mistral"), "cohere": ("provider", "Cohere"),
    "cohere-ai": ("provider", "Cohere"), "groq": ("provider", "Groq"), "groq-sdk": ("provider", "Groq"),
    "together": ("provider", "Together AI"), "replicate": ("provider", "Replicate"),
    "boto3": ("provider?", "AWS (possibly Bedrock)"), "ollama": ("provider", "Ollama"),
    "litellm": ("gateway", "LiteLLM"), "vllm": ("runtime", "vLLM"),
    "transformers": ("runtime", "Hugging Face Transformers"), "llama-cpp-python": ("runtime", "llama.cpp"),
    # frameworks
    "langchain": ("framework", "LangChain"), "langchain-core": ("framework", "LangChain"),
    "langgraph": ("framework", "LangGraph"), "@langchain/core": ("framework", "LangChain"),
    "llama-index": ("framework", "LlamaIndex"), "llama_index": ("framework", "LlamaIndex"),
    "crewai": ("framework", "CrewAI"), "autogen": ("framework", "AutoGen"),
    "pyautogen": ("framework", "AutoGen"), "semantic-kernel": ("framework", "Semantic Kernel"),
    "dspy-ai": ("framework", "DSPy"), "dspy": ("framework", "DSPy"), "haystack-ai": ("framework", "Haystack"),
    "ai": ("framework", "Vercel AI SDK"), "pydantic-ai": ("framework", "PydanticAI"),
    "claude-agent-sdk": ("framework", "Claude Agent SDK"),
    "@anthropic-ai/claude-agent-sdk": ("framework", "Claude Agent SDK"),
    # MCP
    "mcp": ("mcp", "MCP SDK"), "fastmcp": ("mcp", "FastMCP"),
    "@modelcontextprotocol/sdk": ("mcp", "MCP SDK"),
}

_IMPORT_PY = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", re.M)
_IMPORT_JS = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*)["']((?:@[\w\-]+/)?[\w\-.]+)""")
_PY_IMPORT_TO_PKG = {"anthropic": "anthropic", "openai": "openai", "langchain": "langchain",
                     "langchain_core": "langchain-core", "langgraph": "langgraph",
                     "llama_index": "llama-index", "crewai": "crewai", "autogen": "autogen",
                     "semantic_kernel": "semantic-kernel", "dspy": "dspy", "haystack": "haystack-ai",
                     "transformers": "transformers", "vllm": "vllm", "litellm": "litellm",
                     "mistralai": "mistralai", "cohere": "cohere", "groq": "groq",
                     "ollama": "ollama", "mcp": "mcp", "fastmcp": "fastmcp",
                     "pydantic_ai": "pydantic-ai", "claude_agent_sdk": "claude-agent-sdk",
                     "google": None}

_MODEL = re.compile(
    r"""["'`]((?:claude-[a-z0-9][a-z0-9.\-]*)|(?:gpt-[0-9][a-z0-9.\-]*)|(?:o[134](?:-mini|-pro)?)"""
    r"""|(?:gemini-[0-9a-z][a-z0-9.\-]*)|(?:(?:meta-)?llama[-_.]?[0-9][a-z0-9.:\-_]*)"""
    r"""|(?:mi[sx]tral[-_:.a-z0-9]*)|(?:qwen[0-9.]*[-_:.a-z0-9]*)|(?:deepseek-[a-z0-9.\-]+)"""
    r"""|(?:text-embedding-[a-z0-9\-]+)|(?:command-r[-a-z+]*)|(?:phi[0-9][-_:.a-z0-9]*))["'`]""",
    re.I)

SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}")),
    ("OpenAI API key (legacy)", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("Google AI API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("Replicate token", re.compile(r"\br8_[A-Za-z0-9]{30,}\b")),
]
_ENV_ASSIGN = re.compile(
    r"^\s*(?:export\s+)?((?:OPENAI|ANTHROPIC|GOOGLE|GEMINI|MISTRAL|COHERE|GROQ|HF|HUGGINGFACE|"
    r"TOGETHER|REPLICATE|AZURE_OPENAI|DEEPSEEK|XAI)_(?:API_)?(?:KEY|TOKEN))\s*=\s*['\"]?([^\s'\"#]{12,})",
    re.M)

WEIGHT_EXT = {".gguf", ".safetensors", ".onnx", ".pt", ".pth", ".ckpt", ".h5", ".tflite",
              ".mlmodel", ".keras"}
DATA_EXT = {".jsonl", ".parquet", ".arrow"}
PROMPT_EXT = {".prompt", ".prompty"}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    location: str


@dataclass
class Inventory:
    root: str
    providers: dict = field(default_factory=dict)      # display -> {kind, evidence[]}
    models: dict = field(default_factory=dict)         # model id -> [locations]
    mcp_servers: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    prompts: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    files_scanned: int = 0

    def _add_pkg(self, pkg: str, where: str):
        kind, name = PACKAGES[pkg]
        e = self.providers.setdefault(name, {"kind": kind, "packages": set(), "evidence": []})
        e["packages"].add(pkg)
        if where not in e["evidence"] and len(e["evidence"]) < 25:
            e["evidence"].append(where)

    def to_dict(self) -> dict:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "root": self.root,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": {"name": "Redline", "version": __version__},
            "summary": {
                "files_scanned": self.files_scanned,
                "providers": sorted(n for n, v in self.providers.items()
                                    if v["kind"] in ("provider", "provider?", "gateway", "runtime")),
                "frameworks": sorted(n for n, v in self.providers.items() if v["kind"] == "framework"),
                "models": len(self.models), "mcp_servers": len(self.mcp_servers),
                "secrets": len(self.secrets), "prompts": len(self.prompts),
                "artifacts": len(self.artifacts), "findings_by_severity": sev,
            },
            "components": [{"name": n, "kind": v["kind"], "packages": sorted(v["packages"]),
                            "evidence": v["evidence"]} for n, v in sorted(self.providers.items())],
            "models": [{"id": m, "locations": locs[:25]} for m, locs in sorted(self.models.items())],
            "mcp_servers": self.mcp_servers,
            "secrets": self.secrets,
            "prompts": self.prompts,
            "artifacts": self.artifacts,
            "findings": [f.__dict__ for f in sorted(
                self.findings, key=lambda f: ["critical", "high", "medium", "low"].index(f.severity))],
        }


def _rel(root: str, path: str) -> str:
    return os.path.relpath(path, root)


def _read_text(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_TEXT_BYTES:
            return None
        with open(path, "rb") as f:
            raw = f.read()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", "ignore")
    except OSError:
        return None


def _redact(value: str) -> str:
    return value[:8] + "…(redacted)"


def _scan_secrets(inv: Inventory, rel: str, text: str):
    lines = text.splitlines()
    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            if IGNORE_MARK in (lines[ln - 1] if ln - 1 < len(lines) else ""):
                continue
            inv.secrets.append({"kind": kind, "file": rel, "line": ln, "preview": _redact(m.group(0))})
            inv.findings.append(Finding("critical", f"Hardcoded {kind}",
                                        "Live-looking credential committed to the repository. "
                                        "Rotate it and move it to a secret manager.", f"{rel}:{ln}"))
    base = os.path.basename(rel)
    if base.startswith(".env") or base.endswith(".env"):
        for m in _ENV_ASSIGN.finditer(text):
            val = m.group(2)
            if val.startswith("${") or val.lower() in {"changeme", "your_key_here", "xxx"}:
                continue
            ln = text.count("\n", 0, m.start()) + 1
            if any(s["file"] == rel and s["line"] == ln for s in inv.secrets):
                continue
            inv.secrets.append({"kind": f"{m.group(1)} in env file", "file": rel, "line": ln,
                                "preview": _redact(val)})
            inv.findings.append(Finding("high", f"LLM credential in {base}",
                                        "An LLM key sits in an env file inside the repo. "
                                        "Make sure the file is git-ignored and never committed.",
                                        f"{rel}:{ln}"))


def _scan_manifest(inv: Inventory, rel: str, text: str):
    base = os.path.basename(rel)
    names: set[str] = set()
    if base == "package.json":
        try:
            pj = json.loads(text)
            for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                names.update((pj.get(k) or {}).keys())
        except json.JSONDecodeError:
            pass
    elif base.startswith("requirements") and base.endswith(".txt") or base == "Pipfile":
        for line in text.splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)", line)
            if m and not line.strip().startswith("#"):
                names.add(m.group(1).lower())
    else:  # pyproject.toml, setup.cfg, go.mod, Gemfile, etc.: look for quoted/listed names
        for pkg in PACKAGES:
            if re.search(r"""(?:["'\s]|^)""" + re.escape(pkg) + r"""(?:\[[^\]]*\])?\s*(?:[<>=!~;,"']|$)""",
                         text, re.M):
                names.add(pkg)
    for n in names:
        if n in PACKAGES:
            inv._add_pkg(n, rel)


def _scan_code(inv: Inventory, rel: str, text: str, ext: str):
    if ext == ".py" or ext == ".ipynb":
        for m in _IMPORT_PY.finditer(text):
            pkg = _PY_IMPORT_TO_PKG.get(m.group(1))
            if pkg and pkg in PACKAGES:
                inv._add_pkg(pkg, f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
    elif ext in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}:
        for m in _IMPORT_JS.finditer(text):
            name = m.group(1)
            if name in PACKAGES:
                inv._add_pkg(name, f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
    for m in _MODEL.finditer(text):
        mid = m.group(1)
        if len(mid) < 3:
            continue
        loc = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
        inv.models.setdefault(mid, [])
        if loc not in inv.models[mid]:
            inv.models[mid].append(loc)


_UNPINNED_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx"}


def _mcp_risks(name: str, cfg: dict, rel: str) -> list[Finding]:
    out = []
    cmd = cfg.get("command") or ""
    args = [str(a) for a in (cfg.get("args") or [])]
    base = os.path.basename(cmd)
    if base in _UNPINNED_RUNNERS:
        pkgs = [a for a in args if not a.startswith("-")]
        pkg = pkgs[0] if pkgs else ""
        pinned = bool(re.search(r"@\d|==\d", pkg[1:] if pkg.startswith("@") else pkg))
        if pkg and not pinned:
            out.append(Finding("high", f"MCP server '{name}' runs an unpinned package",
                               f"`{base} {pkg}` fetches whatever version is latest at launch. "
                               "Pin an exact version so a compromised release can't slip in.", rel))
    for k, v in (cfg.get("env") or {}).items():
        sv = str(v)
        if sv and not sv.startswith("${") and re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.I) \
                and len(sv) >= 12:
            out.append(Finding("critical", f"MCP server '{name}' has a literal secret in {k}",
                               "Secrets in MCP config files end up in dotfiles and backups. "
                               "Reference an environment variable instead.", rel))
    url = cfg.get("url") or cfg.get("serverUrl") or ""
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.|\[::1\])", url):
        out.append(Finding("medium", f"MCP server '{name}' uses plaintext HTTP",
                           "Tool calls and results cross the network unencrypted. Use HTTPS.", rel))
    if any(a in ("/", "~", os.path.expanduser("~")) for a in args):
        out.append(Finding("medium", f"MCP server '{name}' is scoped to a root or home directory",
                           "A filesystem server rooted at / or ~ exposes far more than a project "
                           "needs. Scope it to the working directory.", rel))
    return out


def _scan_mcp_config(inv: Inventory, rel: str, text: str):
    if "mcpServers" not in text and '"servers"' not in text:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        transport = "http" if (cfg.get("url") or cfg.get("serverUrl")) else "stdio"
        entry = {"name": name, "config_file": rel, "transport": transport,
                 "command": cfg.get("command"), "args": cfg.get("args") or [],
                 "url": cfg.get("url") or cfg.get("serverUrl"),
                 "env_keys": sorted((cfg.get("env") or {}).keys())}
        if transport == "stdio" and cfg.get("command"):
            entry["scan_hint"] = "redline scan --target mcp --command " + json.dumps(
                " ".join([cfg["command"]] + [str(a) for a in entry["args"]]))
        risks = _mcp_risks(name, cfg, rel)
        entry["risks"] = [r.title for r in risks]
        inv.mcp_servers.append(entry)
        inv.findings.extend(risks)


def _scan_prompt_intent(inv: Inventory, rel: str, path: str):
    from .intent import score as _score
    text = _read_text(path)
    if not text:
        return
    for para in re.split(r"\n\s*\n", text):
        r = _score(para)
        if r["flagged"]:
            inv.findings.append(Finding(
                "high", "Future-imperative directive in a prompt file",
                "Text describes a consequential action for a future reader/agent with no "
                "command words, which keyword filters miss. Review this prompt.", rel))
            return


def build_inventory(root: str) -> Inventory:
    root = os.path.abspath(root)
    inv = Inventory(root=root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = _rel(root, path)
            ext = os.path.splitext(fn)[1].lower()
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if ext in WEIGHT_EXT or (ext == ".bin" and size > 10_000_000):
                inv.artifacts.append({"file": rel, "type": "model-weights", "bytes": size})
                continue
            if ext in DATA_EXT:
                inv.artifacts.append({"file": rel, "type": "dataset", "bytes": size})
                continue
            parts = {p.lower() for p in rel.split(os.sep)}
            if ext in PROMPT_EXT or ("prompts" in parts and ext in {".txt", ".md", ".j2", ".jinja",
                                                                     ".jinja2", ".yaml", ".yml"}):
                inv.prompts.append({"file": rel, "bytes": size})
                _scan_prompt_intent(inv, rel, path)
            is_manifest = fn in {"package.json", "pyproject.toml", "Pipfile", "setup.cfg", "go.mod",
                                 "Gemfile", "Cargo.toml"} or (fn.startswith("requirements")
                                                             and fn.endswith(".txt"))
            if not (ext in CODE_EXT or ext in CONFIG_EXT or is_manifest or fn.startswith(".env")):
                continue
            text = _read_text(path)
            if text is None:
                continue
            inv.files_scanned += 1
            _scan_secrets(inv, rel, text)
            if is_manifest:
                _scan_manifest(inv, rel, text)
            if ext in CODE_EXT:
                _scan_code(inv, rel, text, ext)
            if ext == ".json":
                _scan_mcp_config(inv, rel, text)
    if inv.models and not any(v["kind"] in ("provider", "gateway", "runtime")
                              for v in inv.providers.values()):
        inv.findings.append(Finding("low", "Model IDs referenced but no provider SDK found",
                                    "Models may be called over raw HTTP or through a service "
                                    "not declared as a dependency. Worth confirming.", "."))
    return inv


def to_cyclonedx(d: dict) -> dict:
    """CycloneDX 1.6 AI-BOM from an inventory dict."""
    comps = []
    for c in d["components"]:
        comps.append({"type": "framework" if c["kind"] == "framework" else "library",
                      "bom-ref": f"pkg:{c['name']}", "name": c["name"],
                      "properties": [{"name": "redline:kind", "value": c["kind"]},
                                     {"name": "redline:packages", "value": ",".join(c["packages"])}]})
    for m in d["models"]:
        comps.append({"type": "machine-learning-model", "bom-ref": f"model:{m['id']}",
                      "name": m["id"],
                      "properties": [{"name": "redline:location", "value": loc}
                                     for loc in m["locations"][:10]]})
    for a in d["artifacts"]:
        comps.append({"type": "machine-learning-model" if a["type"] == "model-weights" else "data",
                      "bom-ref": f"file:{a['file']}", "name": a["file"],
                      "properties": [{"name": "redline:bytes", "value": str(a["bytes"])}]})
    services = []
    for s in d["mcp_servers"]:
        svc = {"bom-ref": f"mcp:{s['name']}", "name": s["name"],
               "properties": [{"name": "redline:transport", "value": s["transport"]},
                              {"name": "redline:config", "value": s["config_file"]}]
               + [{"name": "redline:risk", "value": r} for r in s["risks"]]}
        if s.get("url"):
            svc["endpoints"] = [s["url"]]
        if s.get("command"):
            svc["properties"].append({"name": "redline:command",
                                      "value": " ".join([s["command"]] + [str(x) for x in s["args"]])})
        services.append(svc)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": d["generated"],
            "tools": {"components": [{"type": "application", "name": "Redline",
                                      "version": d["tool"]["version"]}]},
            "component": {"type": "application", "name": os.path.basename(d["root"]) or d["root"]},
        },
        "components": comps,
        "services": services,
    }
