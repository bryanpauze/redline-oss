"""Capability-graph exfiltration certifier.

Model-level defense against prompt injection is provably unwinnable, so this does
not try. It proves a property of the AGENT'S ARCHITECTURE instead: whether the tool
graph can leak at all, regardless of how thoroughly the model is jailbroken.

Exfiltration needs the lethal trifecta in one place: exposure to untrusted content
(ingress), access to private data (private source), and a way out (external or exec
sink). In an LLM agent with no information-flow controls, every tool output passes
through the model's context, so any output can influence any later tool call. The
sound, conservative assumption is therefore that the context is a fully-connected
medium: if all three trifecta legs are present and no declared control cuts one, an
exfiltration path exists.

Soundness direction: this over-approximates connectivity, so it NEVER falsely
certifies a leaky agent as safe. It can over-block (call a benign agent unsafe),
which is the correct failure direction for a safety certificate. The certificate is
relative to the tool labeling and the declared controls, and says so.
"""
from __future__ import annotations

import re
import time

from .. import __version__
from .evidence import sign_document

# capability roles
INGRESS = "untrusted_ingress"      # pulls in attacker-controllable / third-party content
PRIVATE = "private_source"         # yields private / sensitive data
EXTERNAL_SINK = "external_sink"    # can send data out of the trust boundary
EXEC_SINK = "exec_sink"            # executes (a covert exfil + blast-radius channel)

_ROLE_PATTERNS = {
    INGRESS: re.compile(
        r"\b(read|fetch|get|search|browse|web|url|http|https|email|inbox|mail|message|"
        r"messages|issue|ticket|comment|review|document|doc|docs|retrieve|list|load|"
        r"scrape|rss|feed|pull|slack|discord|calendar|notion|drive|sheet|page|content|"
        r"download|open|receive)\b", re.I),
    PRIVATE: re.compile(
        r"\b(secret|secrets|credential|credentials|token|password|passwd|api[_ -]?key|"
        r"key|keys|config|configuration|env|environment|private|internal|vault|db|"
        r"database|customer|user[_ -]?data|pii|ssn|record|records|financial|salary|"
        r"health|profile|account|read[_ -]?file|readfile|filesystem|\.env|id_rsa)\b", re.I),
    EXTERNAL_SINK: re.compile(
        r"\b(send|post|put|email|e-?mail|webhook|http|https|url|fetch|publish|upload|"
        r"share|forward|notify|sms|tweet|slack|discord|export|transmit|write[_ -]?file|"
        r"create[_ -]?(comment|issue|pr|page)|reply|dispatch|deploy)\b", re.I),
    EXEC_SINK: re.compile(
        r"\b(exec|execute|run|run[_ -]?command|shell|bash|sh|cmd|command|eval|spawn|"
        r"subprocess|code|python|node|sql|delete|drop|unlink|rm|remove|deploy|install)\b",
        re.I),
}


ALL_ROLES = [INGRESS, PRIVATE, EXTERNAL_SINK, EXEC_SINK]


def _split_identifiers(text: str) -> str:
    """fetchUrl / get_credentials / slack-post -> 'fetch Url' / 'get credentials' /
    'slack post', so the word-boundary role patterns see identifier parts."""
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    return re.sub(r"[_\-.]+", " ", text)


def label_tool(tool: dict) -> list[str]:
    """Assign capability roles to a tool from its name, description, and schema.

    Errs toward labeling, for soundness: a tool that matches a role is given it, and a
    tool the keyword taxonomy can't place at all is assumed capable of EVERY role
    (an unknown tool could be any of them). An operator who knows better declares the
    roles explicitly with a "redline_roles" list on the tool entry."""
    import json as _j
    declared = tool.get("redline_roles")
    if isinstance(declared, list):
        return [r for r in ALL_ROLES if r in declared]
    blob = " ".join([tool.get("name", ""), tool.get("description", "") or "",
                     _j.dumps(tool.get("inputSchema") or tool.get("input_schema") or {})])
    views = (blob, _split_identifiers(blob))
    roles = [r for r, rx in _ROLE_PATTERNS.items() if any(rx.search(v) for v in views)]
    return roles or list(ALL_ROLES)


def _witnesses(tools: list[dict], role: str) -> list[str]:
    return sorted(t["name"] for t in tools if role in t.get("_roles", []))


def certify_graph(tools: list[dict], *, untrusted_input: bool = True,
                  private_in_context: bool = True, mitigations: list[str] | None = None,
                  target: str = "agent") -> dict:
    """Certify whether the tool graph can exfiltrate.

    untrusted_input: does any untrusted content enter the agent at all? Default True
        (the safe assumption). Set False only if the operator asserts a closed agent
        with no third-party/user-controlled content.
    private_in_context: is any private data reachable in the agent's context (the
        system prompt, the conversation, retrieved data)? Default True, the safe
        assumption; declare the 'no_private_data' mitigation to assert otherwise.
    mitigations: declared controls that soundly cut a trifecta leg. Recognized:
        'no_untrusted_input'  - asserts no untrusted content reaches the model
        'no_private_data'     - asserts no private data is in scope
        'egress_allowlist'    - external sinks are default-deny allowlisted (cuts the
                                EXTERNAL_SINK leg; does NOT cut EXEC_SINK)
        'quarantine'          - untrusted content is processed by a tool-less model
                                (dual-LLM / CaMeL), cutting untrusted->action influence
        'human_approval_sinks'- every sink call requires human approval (cuts the sink leg)
    """
    mit = set(mitigations or [])
    # work on copies (never mutate the caller's tool list) and skip malformed entries
    tools = [dict(t, name=str(t["name"])) for t in tools
             if isinstance(t, dict) and t.get("name") not in (None, "")]
    for t in tools:
        t["_roles"] = label_tool(t)

    ingress_tools = _witnesses(tools, INGRESS)
    private_tools = _witnesses(tools, PRIVATE)
    ext_sinks = _witnesses(tools, EXTERNAL_SINK)
    exec_sinks = _witnesses(tools, EXEC_SINK)

    # resolve each leg under declarations + mitigations
    ingress = (untrusted_input or bool(ingress_tools))
    if "no_untrusted_input" in mit and not ingress_tools:
        ingress = False
    if "quarantine" in mit:
        ingress = False   # untrusted content can no longer influence tool calls

    private = private_in_context or bool(private_tools)
    if "no_private_data" in mit and not private_tools:
        private = False

    sink_ext = bool(ext_sinks) and "egress_allowlist" not in mit and "human_approval_sinks" not in mit
    sink_exec = bool(exec_sinks) and "human_approval_sinks" not in mit
    sink = sink_ext or sink_exec

    trifecta = ingress and private and sink
    # which leg is absent (why it's safe), or the witnesses (why it's not)
    if not trifecta:
        absent = []
        if not ingress:
            absent.append("untrusted ingress")
        if not private:
            absent.append("private data")
        if not sink:
            absent.append("external/exec sink")
        status, verdict = "no_exfiltration_path", (
            f"no exfiltration path: the trifecta leg(s) [{', '.join(absent)}] "
            "are absent or cut by a declared control")
        paths = []
    else:
        status, verdict = "exfiltration_path_exists", (
            "the lethal trifecta is present and connected through the model context; "
            "a hijacked model can move private data to a sink")
        paths = [{"ingress": ingress_tools or ["<untrusted user/retrieved input>"],
                  "private": private_tools or ["<private data in context>"],
                  "sink": sorted(set((ext_sinks if sink_ext else []) +
                                     (exec_sinks if sink_exec else [])))}]

    doc = {
        "certificate_version": "v1",
        "kind": "exfiltration-path",
        "tool": {"name": "Redline", "version": __version__},
        "target": target,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "verdict": verdict,
        "trifecta": {
            "untrusted_ingress": {"present": ingress, "tools": ingress_tools},
            "private_source": {"present": private, "tools": private_tools},
            "external_sink": {"present": sink_ext, "tools": ext_sinks},
            "exec_sink": {"present": sink_exec, "tools": exec_sinks},
        },
        "exfiltration_paths": paths,
        "declared_mitigations": sorted(mit),
        "tool_labels": {t["name"]: t["_roles"] for t in tools},
        "soundness": (
            "Sound over this tool labeling under the conservative assumption that the "
            "agent context is a fully-connected medium (any tool output may influence "
            "any later tool call). Labels come from a keyword taxonomy over each tool's "
            "name, description, and schema; a tool it cannot place is assumed capable of "
            "every role. Over-approximates: may over-block. Not valid if a tool's "
            "declared redline_roles, its description, or the declared mitigations are wrong."),
    }
    return sign_document(doc)


def _load_tools_mcp(endpoint: str, transport: str) -> tuple[list[dict], str]:
    from .mcp_client import MCPClient, MCPHTTPClient
    client = (MCPHTTPClient(endpoint) if transport == "http" else MCPClient(endpoint))
    try:
        client.start()
        client.initialize()
        name = "mcp:" + (client.server_info.get("name") or "server")
        tools = [t for t in (client.list_tools() or []) if isinstance(t, dict) and t.get("name")]
    finally:
        client.close()
    return tools, name


def certify_mcp(endpoint: str, transport: str = "stdio", **kw) -> dict:
    tools, name = _load_tools_mcp(endpoint, transport)
    return certify_graph(tools, target=name, **kw)
