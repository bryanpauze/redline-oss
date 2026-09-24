"""Render a ScanResult as a standalone HTML report."""
from __future__ import annotations

import html
import json

from .runner import ScanResult

GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}
SEV_COLOR = {"low": "#0891b2", "medium": "#d97706", "high": "#ea580c", "critical": "#dc2626"}
VERDICT_COLOR = {"confirmed": "#dc2626", "intermittent": "#d97706", "detected": "#ea580c",
                 "unverified": "#6b7280", "clean": "#16a34a", "error": "#6b7280"}


def _card(r) -> str:
    status = "VULNERABLE" if r["vulnerable"] else ("ERROR" if r["error"] else "passed")
    scolor = "#dc2626" if r["vulnerable"] else ("#6b7280" if r["error"] else "#16a34a")
    sev = html.escape(r["severity"].upper())
    body = html.escape(r["error"] or r["response_excerpt"] or "(empty response)")
    rem = f'<div class="rem"><b>Fix:</b> {html.escape(r["remediation"])}</div>' if r["vulnerable"] else ""
    # multi-trial line: verdict badge + fire rate + Wilson CI (only when >1 trial or a verdict is set)
    stat = ""
    verdict = r.get("verdict") or ""
    trials = r.get("trials", 1)
    if verdict and (trials > 1 or verdict == "unverified"):
        vc = VERDICT_COLOR.get(verdict, "#6b7280")
        n_valid = trials - r.get("errors", 0)
        rate = f'{int(round(100 * r.get("fire_rate", 0)))}% ({r.get("fires", 0)}/{n_valid})'
        ci = f'95% CI {int(round(100*r.get("ci_low",0)))}\u2013{int(round(100*r.get("ci_high",0)))}%'
        jt = r.get("judge_trials")
        judge = (f' \u00b7 validator agreed {r.get("judge_confirmed",0)}/{jt}'
                 if jt else "")
        stat = (f'<div class="stat"><span class="verdict" style="background:{vc}">{html.escape(verdict)}</span>'
                f'<span class="rate">fired {rate} \u00b7 {ci}{judge}</span></div>')
    return f"""
    <div class="card {'vuln' if r['vulnerable'] else ''}">
      <div class="chead">
        <span class="pid">{html.escape(r['id'])}</span>
        <span class="sev" style="background:{SEV_COLOR.get(r['severity'],'#666')}">{sev}</span>
        <span class="title">{html.escape(r['title'])}</span>
        <span class="status" style="color:{scolor}">{status}</span>
      </div>
      <div class="desc">{html.escape(r['description'])}</div>
      {stat}
      <div class="resp"><b>Target reply:</b> {body}</div>
      {rem}
    </div>"""


def render_html(res: ScanResult) -> str:
    d = res.to_dict()
    g = d["grade"]
    gc = GRADE_COLOR.get(g, "#666")
    cats = "".join(
        f'<div class="pill"><b>{html.escape(k)}</b> {v["fired"]}/{v["total"]} vulnerable</div>'
        for k, v in d["summary"]["by_category"].items()
    )
    cards = "".join(_card(r) for r in d["results"])
    nerr = d["summary"].get("errors", 0)
    errbar = (f'<div class="pill" style="border-color:#d97706;color:#f59e0b">'
              f'&#9888; {nerr} probe(s) could not reach the target &mdash; results partial</div>'
              if nerr else "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Redline Security Report — {html.escape(d['target'])}</title>
<style>
:root{{--bg:#0b0e14;--panel:#141924;--ink:#e6e9ef;--mut:#9aa4b2;--line:#232b3a}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:32px}}
.wrap{{max-width:900px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}} .sub{{color:var(--mut);margin-bottom:24px}}
.hero{{display:flex;gap:24px;align-items:center;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px;margin-bottom:20px}}
.grade{{font-size:56px;font-weight:800;line-height:1;width:96px;height:96px;display:flex;align-items:center;justify-content:center;border-radius:16px;color:#fff;background:{gc}}}
.metrics{{display:flex;gap:28px;flex-wrap:wrap}}
.metric .n{{font-size:28px;font-weight:700}} .metric .l{{color:var(--mut);font-size:13px}}
.pills{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 26px}}
.pill{{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:6px 14px;font-size:13px;color:var(--mut)}}
.pill b{{color:var(--ink);text-transform:capitalize}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid #16a34a;border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.card.vuln{{border-left-color:#dc2626}}
.chead{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.pid{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mut)}}
.sev{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px}}
.title{{font-weight:600}} .status{{margin-left:auto;font-weight:700;font-size:12px;letter-spacing:.5px}}
.desc{{color:var(--mut);font-size:13px;margin:8px 0}}
.resp{{background:#0b0e14;border:1px solid var(--line);border-radius:8px;padding:10px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#c9d1d9;white-space:pre-wrap;word-break:break-word}}
.rem{{margin-top:10px;font-size:13px;color:#fca5a5}}
footer{{color:var(--mut);font-size:12px;margin-top:28px;text-align:center}}
</style></head><body><div class="wrap">
<h1>Redline — LLM Security Report</h1>
<div class="sub">Target: <b>{html.escape(d['target'])}</b> · {html.escape(d['started'])} · {d['duration_s']}s · {d.get('trials',1)} trial(s){" · validator " + html.escape(d.get("validator","none")) if d.get("validator","none") != "none" else ""}</div>
<div class="hero">
  <div class="grade">{g}</div>
  <div class="metrics">
    <div class="metric"><div class="n">{d['score']}/100</div><div class="l">risk score (higher = worse)</div></div>
    <div class="metric"><div class="n" style="color:#dc2626">{d['summary']['vulnerable']}</div><div class="l">vulnerabilities</div></div>
    <div class="metric"><div class="n" style="color:#ea580c">{d['summary'].get('confirmed',0)}</div><div class="l">confirmed</div></div>
    <div class="metric"><div class="n">{d['summary']['probes']}</div><div class="l">probes run</div></div>
  </div>
</div>
<div class="pills">{errbar}{cats}</div>
{cards}
<footer>Generated by Redline · defensive LLM security scanner · for authorized testing only</footer>
</div></body></html>"""


def render_json(res: ScanResult) -> str:
    return json.dumps(res.to_dict(), indent=2)


def render_comparison(results: list[ScanResult]) -> str:
    """Side-by-side benchmark of several targets."""
    rows = ""
    # union of probe ids in registry order (from first result)
    probe_ids = [r["id"] for r in results[0].to_dict()["results"]] if results else []
    dds = [r.to_dict() for r in results]
    head = "".join(f"<th>{html.escape(d['target'])}</th>" for d in dds)
    # summary row
    def cell(d):
        g = d["grade"]; c = GRADE_COLOR.get(g, "#666")
        return (f'<td class="gcell"><span class="gg" style="background:{c}">{g}</span>'
                f'<span class="gs">{d["score"]}/100 · {d["summary"]["vulnerable"]}/{d["summary"]["probes"]}</span></td>')
    summary = "<tr class='sumrow'><td>Overall</td>" + "".join(cell(d) for d in dds) + "</tr>"
    # per-probe rows
    idx = {d["target"]: {r["id"]: r for r in d["results"]} for d in dds}
    titles = {r["id"]: (r["title"], r["severity"]) for r in dds[0]["results"]}
    for pid in probe_ids:
        title, sev = titles[pid]
        cells = ""
        for d in dds:
            r = idx[d["target"]].get(pid)
            if r is None:
                cells += "<td>–</td>"; continue
            if r["error"]:
                cells += '<td class="err">err</td>'
            elif r["vulnerable"]:
                cells += '<td class="bad">✗ vuln</td>'
            else:
                cells += '<td class="ok">✓ pass</td>'
        rows += (f'<tr><td class="pcell"><span class="pid">{html.escape(pid)}</span> '
                 f'<span class="sev" style="background:{SEV_COLOR.get(sev,"#666")}">{html.escape(sev.upper())}</span> '
                 f'{html.escape(title)}</td>{cells}</tr>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Redline Benchmark</title><style>
:root{{--bg:#0b0e14;--panel:#141924;--ink:#e6e9ef;--mut:#9aa4b2;--line:#232b3a}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:32px}}
.wrap{{max-width:960px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}} .sub{{color:var(--mut);margin-bottom:22px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{padding:11px 12px;text-align:center;border-bottom:1px solid var(--line);font-size:13px}}
th:first-child,td:first-child{{text-align:left}}
th{{background:#0f141d;color:var(--mut);font-weight:600}}
.pcell{{color:var(--ink)}} .pid{{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--mut)}}
.sev{{color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:5px}}
.bad{{color:#f87171;font-weight:600}} .ok{{color:#4ade80}} .err{{color:#9aa4b2}}
.sumrow td{{background:#0f141d;font-weight:700;border-bottom:2px solid var(--line)}}
.gcell{{}} .gg{{display:inline-block;color:#fff;font-weight:800;padding:2px 10px;border-radius:7px;margin-right:6px}}
.gs{{color:var(--mut);font-weight:500;font-size:12px}}
footer{{color:var(--mut);font-size:12px;margin-top:24px;text-align:center}}
</style></head><body><div class="wrap">
<h1>Redline — model security benchmark</h1>
<div class="sub">Lower score = safer. Each ✗ is a probe the target failed (was successfully attacked).</div>
<table><thead><tr><th>Probe</th>{head}</tr></thead>
<tbody>{summary}{rows}</tbody></table>
<footer>Generated by Redline · defensive LLM security scanner · for authorized testing only</footer>
</div></body></html>"""
