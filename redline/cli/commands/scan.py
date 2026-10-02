"""`scan` and `benchmark`: run the probe suite against a target and report."""
from __future__ import annotations

import sys

from ...core import baseline as bl
from ...core.report import render_comparison, render_html, render_json
from ...core.runner import run_scan
from ...core.sarif import to_sarif
from ...core.target import OllamaTarget
from ..shared import add_target_args, build_target, progress, write_json


def emit(res, a) -> int:
    d = res.to_dict()
    if a.out:
        with open(a.out, "w") as f:
            f.write(render_html(res))
    if a.json:
        with open(a.json, "w") as f:
            f.write(render_json(res))
    if a.sarif:
        write_json(a.sarif, to_sarif(d, anchor=a.sarif_anchor))
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


def cmd_scan(a) -> int:
    if a.target == "mcp":
        from ...core.mcp_scan import scan_mcp
        if not (a.command or a.url):
            sys.exit("error: --target mcp needs --command (stdio) or --url (http)")
        res = scan_mcp(a.command or a.url)
        return emit(res, a)

    target = build_target(a)
    if not a.quiet:
        print(f"redline: scanning {target.name}", file=sys.stderr)
    only = None
    if a.profile:
        from ...core.profiles import get_profile
        only = get_profile(a.profile).categories
    from ...core.validator import build_judge
    from ...probes import ScanContext
    res = run_scan(target, ctx=ScanContext.random(), trials=a.trials,
                   validator=build_judge(a.judge), polymorph=a.polymorph, only=only,
                   deployed=a.deployed, app_canary=a.app_canary,
                   progress=None if a.quiet else progress)
    return emit(res, a)


def cmd_benchmark(a) -> int:
    results = []
    for m in a.models:
        print(f"redline: scanning {m}", file=sys.stderr)
        t = 0.0 if a.trials <= 1 else 0.7
        results.append(run_scan(OllamaTarget(model=m, host=a.host, temperature=t),
                                trials=a.trials))
    with open(a.out, "w") as f:
        f.write(render_comparison(results))
    print(f"\n  Benchmark report: {a.out}")
    for r in results:
        print(f"    {r.target:30} {r.grade()}  {r.score():3}/100  {len(r.fired)} vuln")
    return 0


def register(sub) -> None:
    s = sub.add_parser("scan", help="run the probe suite against a target")
    add_target_args(s)
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
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("benchmark", help="scan several Ollama models; one comparison report")
    b.add_argument("--models", nargs="+", required=True)
    b.add_argument("--host", default="http://localhost:11434")
    b.add_argument("--trials", type=int, default=1)
    b.add_argument("--out", default="benchmark.html")
    b.set_defaults(func=cmd_benchmark)
