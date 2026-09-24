"""Redline (Open Source): scan LLMs, agents, and MCP servers for injection, jailbreak,
and leakage flaws. The community scanner. The autonomous agent team, adaptive robustness
certification, governance, and the hosted platform are in Redline Enterprise."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .core import baseline as bl
from .core.report import render_comparison, render_html, render_json
from .core.runner import run_scan
from .core.sarif import to_sarif
from .core.target import AnthropicTarget, MockTarget, OllamaTarget, OpenAICompatTarget

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPEN_WEIGHT_TARGETS = ["vllm", "llamacpp", "tgi", "lmstudio", "together", "groq",
                       "openrouter", "fireworks", "deepinfra", "completion"]


def _temperature(a):
    if a.temperature is not None:
        return a.temperature
    return 0.0 if a.trials <= 1 else 0.7


def _build_target(a):
    t = _temperature(a)
    if a.target == "mock":
        return MockTarget()
    if a.target == "guarded":
        from .core.target import GuardedMockTarget
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
    from .core.target import OPENAI_COMPAT_PRESETS
    if a.target in OPENAI_COMPAT_PRESETS:
        from .core.target import preset_target
        _u, env = OPENAI_COMPAT_PRESETS[a.target]
        key = a.api_key or os.environ.get(env) or os.environ.get("REDLINE_TARGET_API_KEY")
        host = a.url or (a.host if getattr(a, "host", None)
                         and a.host != "http://localhost:11434" else None)
        return preset_target(a.target, model=a.model or "default", api_key=key,
                             host=host, temperature=t)
    if a.target == "completion":
        from .core.target import TextCompletionTarget
        return TextCompletionTarget(url=a.url or "http://localhost:8080/completion",
                                    model=a.model or "default",
                                    api_key=a.api_key or os.environ.get("REDLINE_TARGET_API_KEY"),
                                    template=getattr(a, "template", "chatml"), temperature=t)
    sys.exit(f"unknown target: {a.target}")


def _progress(i, n, p):
    print(f"  [{i}/{n}] {p.id} {p.title}...", file=sys.stderr)


def _emit(res, a) -> int:
    d = res.to_dict()
    if a.out:
        open(a.out, "w").write(render_html(res))
    if a.json:
        open(a.json, "w").write(render_json(res))
    if a.sarif:
        json.dump(to_sarif(d, anchor=a.sarif_anchor), open(a.sarif, "w"), indent=2)
    delta = bl.diff(d, bl.load(a.baseline)) if a.baseline else None
    print()
    print(f"  Target : {res.target}")
    print(f"  Grade  : {res.grade()}   Risk score: {res.score()}/100"
          + (f"   Trials: {res.trials}" if res.trials > 1 else ""))
    print(f"  Result : {len(res.fired)}/{len(res.results)} probes found vulnerabilities")
    for r in res.fired:
        print(f"    ✗ {r.id} [{r.severity}] {r.title}")
    if not res.fired:
        print("    ✓ no vulnerabilities detected")
    if delta is not None:
        print(f"\n  vs baseline: {len(delta['new'])} new, {len(delta['fixed'])} fixed")
    for label, path in (("HTML", a.out), ("JSON", a.json), ("SARIF", a.sarif)):
        if path:
            print(f"  {label}: {path}")
    if res.inconclusive:
        return 2
    return 1 if bl.should_fail(d, a.fail_on, delta) else 0


def _add_target_args(s):
    s.add_argument("--target", default="mock",
                   choices=["mock", "guarded", "ollama", "openai", "anthropic", "http",
                            "mcp", *OPEN_WEIGHT_TARGETS])
    s.add_argument("--model", default=None)
    s.add_argument("--host", default="http://localhost:11434")
    s.add_argument("--url", default=None)
    s.add_argument("--template", default="chatml",
                   choices=["chatml", "llama3", "alpaca", "mistral", "plain"])
    s.add_argument("--api-key", default=None)
    s.add_argument("--temperature", type=float, default=None)
    s.add_argument("--command", default=None, help="launch command for --target mcp")


def main(argv=None):
    from . import __version__
    ap = argparse.ArgumentParser(prog="redline", description=__doc__)
    ap.add_argument("--version", action="version", version=f"redline {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the probe suite against a target")
    _add_target_args(s)
    s.add_argument("--trials", type=int, default=1)
    s.add_argument("--polymorph", type=int, default=1,
                   help="run each probe in N mutated surface forms")
    s.add_argument("--judge", default=None, help="independent validator, e.g. ollama:llama3.1:8b")
    s.add_argument("--deployed", action="store_true", help="scan a deployed app (generic-leak)")
    s.add_argument("--app-canary", default=None, help="a known secret in your app to detect")
    s.add_argument("--profile", default=None, help="scan profile (see: redline profiles)")
    s.add_argument("--out", default=None, help="write HTML report")
    s.add_argument("--json", default=None, help="write JSON report")
    s.add_argument("--sarif", default=None, help="write SARIF 2.1.0 (GitHub code scanning)")
    s.add_argument("--sarif-anchor", default=None)
    s.add_argument("--baseline", default=None, help="diff against a previous scan")
    s.add_argument("--fail-on", choices=["any", "new", "none"], default="any")
    s.add_argument("--quiet", action="store_true")

    sub.add_parser("probes", help="list the probe suite with framework mappings")
    sub.add_parser("profiles", help="list scan-profile bundles")

    gd = sub.add_parser("golden", help="run a profile's golden detector-regression set")
    gd.add_argument("--profile", default="general")

    cv = sub.add_parser("covert", help="measure covert-channel exfiltration capacity")
    _add_target_args(cv)
    cv.add_argument("--trials", type=int, default=1)

    fp = sub.add_parser("fingerprint", help="name a target's guardrail defense class")
    _add_target_args(fp)
    fp.add_argument("--trials", type=int, default=1)

    xc = sub.add_parser("exfil-cert", help="prove (soundly) whether an agent's tool graph "
                                           "can exfiltrate the lethal trifecta")
    xc.add_argument("--mcp-command", default=None)
    xc.add_argument("--mcp-url", default=None)
    xc.add_argument("--tools", default=None, help="tool-list JSON instead of a live MCP server")
    xc.add_argument("--mitigation", action="append", default=[],
                    help="declared control: egress_allowlist, quarantine, human_approval_sinks, "
                         "no_untrusted_input, no_private_data")
    xc.add_argument("--out", default=None)

    ve = sub.add_parser("verify-evidence", help="verify a signed certificate or bundle")
    ve.add_argument("path")

    cov = sub.add_parser("coverage", help="NIST AI 100-2e adversarial-ML coverage matrix")
    cov.add_argument("--out", default=None)
    cov.add_argument("--json", default=None)

    st = sub.add_parser("shadow-text", help="heuristic: is text likely AI-authored?")
    st.add_argument("path")

    el = sub.add_parser("egress-scan", help="find shadow AI in DNS/proxy/firewall logs")
    el.add_argument("logs", nargs="+")
    el.add_argument("--inventory", default=None)
    el.add_argument("--fail-on-shadow", action="store_true")

    inv = sub.add_parser("inventory", help="AI-BOM: models, SDKs, MCP servers, prompts, secrets")
    inv.add_argument("path", nargs="?", default=".")
    inv.add_argument("--json", default=None)
    inv.add_argument("--cyclonedx", default=None)
    inv.add_argument("--fail-on", choices=["none", "critical", "high"], default="none")

    b = sub.add_parser("benchmark", help="scan several Ollama models; one comparison report")
    b.add_argument("--models", nargs="+", required=True)
    b.add_argument("--host", default="http://localhost:11434")
    b.add_argument("--trials", type=int, default=1)
    b.add_argument("--out", default="benchmark.html")

    a = ap.parse_args(argv)

    if a.cmd == "probes":
        from .core.compliance import mapping
        from .probes import all_probes
        for p in all_probes():
            m = mapping(p.id)
            print(f"{p.id:8} [{p.severity:8}] {p.category:14} {p.title}")
            tags = m["owasp"] + m["atlas"]
            if tags:
                print(f"         {' '.join(tags)}")
        return 0

    if a.cmd == "profiles":
        from .core.profiles import BUILTIN_PROFILES
        for name, prof in BUILTIN_PROFILES.items():
            print(f"  {name:16} {', '.join(prof.categories)}")
        return 0

    if a.cmd == "golden":
        from .core.profiles import get_profile, run_golden
        r = run_golden(get_profile(a.profile).golden)
        ok, tot = r.get("passed", 0), r.get("total", 0)
        print(f"  golden[{a.profile}]: {ok}/{tot} passed")
        return 0 if ok == tot else 1

    if a.cmd == "coverage":
        from .core import coverage as cov_mod
        from .probes import all_probes
        c = cov_mod.build(all_probes())
        print(cov_mod.render_text(c))
        if a.out:
            open(a.out, "w").write(cov_mod.render_markdown(c))
            print(f"\n  Markdown: {a.out}")
        if a.json:
            json.dump(c, open(a.json, "w"), indent=2)
        return 0

    if a.cmd == "covert":
        from .core.covert import measure_covert
        r = measure_covert(_build_target(a))
        print(json.dumps(r, indent=2) if not sys.stdout.isatty() else r.get("summary", r))
        return 0

    if a.cmd == "fingerprint":
        from .core.fingerprint import fingerprint
        r = fingerprint(_build_target(a))
        print(f"\n  Target: {r['target']}\n  Defense class: {r['defense_class']}\n  {r['reason']}")
        return 0

    if a.cmd == "exfil-cert":
        from .core.exfilcert import certify_graph, certify_mcp
        if a.tools:
            tools = json.load(open(a.tools))
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
            json.dump(doc, open(a.out, "w"), indent=2)
        return 1 if doc["status"] == "exfiltration_path_exists" else 0

    if a.cmd == "verify-evidence":
        from .core.evidence import verify_document
        r = verify_document(json.load(open(a.path)))
        print(f"  {'VALID' if r['ok'] else 'INVALID'}: {r['reason']}")
        return 0 if r["ok"] else 1

    if a.cmd == "shadow-text":
        from .core.shadow_ai import classify_text
        r = classify_text(open(a.path).read())
        print(f"  AI-authored likelihood: {r['score']:.2f}  ({r['label']})")
        return 0

    if a.cmd == "egress-scan":
        from .core.egresslog import analyze_lines, shadow_delta
        lines = []
        for path in a.logs:
            lines += open(path, errors="ignore").read().splitlines()
        egress = analyze_lines(lines)
        inv = json.load(open(a.inventory)) if a.inventory else None
        delta = shadow_delta(egress, inv)
        print(f"\n  Providers on the wire: {', '.join(egress.get('providers', {})) or '-'}")
        print(f"  Shadow AI (seen but not in code): {', '.join(delta['shadow']) or 'none'}")
        return 1 if (a.fail_on_shadow and delta["shadow"]) else 0

    if a.cmd == "inventory":
        return _inventory(a)

    if a.cmd == "benchmark":
        results = []
        for m in a.models:
            print(f"redline: scanning {m}", file=sys.stderr)
            t = 0.0 if a.trials <= 1 else 0.7
            results.append(run_scan(OllamaTarget(model=m, host=a.host, temperature=t),
                                    trials=a.trials))
        open(a.out, "w").write(render_comparison(results))
        print(f"\n  Benchmark report: {a.out}")
        for r in results:
            print(f"    {r.target:30} {r.grade()}  {r.score():3}/100  {len(r.fired)} vuln")
        return 0

    # scan
    if a.target == "mcp":
        from .core.mcp_scan import scan_mcp
        if not (a.command or a.url):
            sys.exit("error: --target mcp needs --command (stdio) or --url (http)")
        res = scan_mcp(a.command or a.url)
        return _emit(res, a)

    target = _build_target(a)
    if not a.quiet:
        print(f"redline: scanning {target.name}", file=sys.stderr)
    only = None
    if a.profile:
        from .core.profiles import get_profile
        only = get_profile(a.profile).categories
    from .core.validator import build_judge
    from .probes import ScanContext
    res = run_scan(target, ctx=ScanContext.random(), trials=a.trials,
                   validator=build_judge(a.judge), polymorph=a.polymorph, only=only,
                   deployed=a.deployed, app_canary=a.app_canary,
                   progress=None if a.quiet else _progress)
    return _emit(res, a)


def _inventory(a) -> int:
    from .core.inventory import build_inventory, to_cyclonedx
    d = build_inventory(a.path).to_dict()
    sm = d["summary"]
    if a.json:
        json.dump(d, open(a.json, "w"), indent=2)
    if a.cyclonedx:
        json.dump(to_cyclonedx(d), open(a.cyclonedx, "w"), indent=2)
    print(f"\n  AI inventory of {d['root']}  ({sm['files_scanned']} files)")
    print(f"  Providers : {', '.join(sm['providers']) or '-'}")
    print(f"  Models    : {', '.join(m['id'] for m in d['models'][:12]) or '-'}")
    print(f"  MCP servers: {', '.join(s['name'] for s in d['mcp_servers']) or '-'}")
    for f in d["findings"]:
        print(f"    [{f['severity']:8}] {f['title']}  ({f['location']})")
    order = ["critical", "high", "medium", "low"]
    if a.fail_on == "none":
        return 0
    return 1 if any(order.index(f["severity"]) <= order.index(a.fail_on)
                    for f in d["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
