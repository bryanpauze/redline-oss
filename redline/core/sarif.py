"""SARIF 2.1.0 output, so Redline findings land in GitHub code scanning (and any
other SARIF consumer) next to the rest of a team's security alerts."""
from __future__ import annotations

import hashlib

from .. import __version__
from .compliance import labels, mapping

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEC_SEV = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5"}


def to_sarif(scan: dict, anchor: str = "redline.target") -> dict:
    """Convert a Redline result dict (ScanResult.to_dict()) to a SARIF log.

    `anchor` is the repository path alerts attach to. An LLM endpoint has no source
    file, so point this at whatever file configures the target (a prompt file, an
    MCP config, or a small `redline.target` marker file).
    """
    rules, results = [], []
    for r in scan["results"]:
        m = mapping(r["id"])
        rules.append({
            "id": r["id"],
            "name": r["title"].replace(" ", ""),
            "shortDescription": {"text": r["title"]},
            "fullDescription": {"text": r["description"]},
            "help": {"text": r.get("remediation") or r["description"],
                     "markdown": f"**Fix:** {r.get('remediation') or ''}\n\n"
                                 + "\n".join(f"- {x}" for x in labels(r["id"]))},
            "properties": {
                "tags": ["security", "llm", r["category"]] + m["owasp"] + m["atlas"],
                "security-severity": _SEC_SEV.get(r["severity"], "5.0"),
                "precision": "very-high",
            },
        })
        if not r.get("vulnerable"):
            continue
        rate = ""
        if r.get("trials", 1) > 1:
            rate = (f" Fired {r.get('fires')}/{r.get('trials') - r.get('errors', 0)} trials "
                    f"(95% CI {r.get('ci_low', 0):.0%}-{r.get('ci_high', 0):.0%}), "
                    f"verdict: {r.get('verdict')}.")
        fp = hashlib.sha256(f"{scan['target']}|{r['id']}".encode()).hexdigest()
        results.append({
            "ruleId": r["id"],
            "level": _LEVEL.get(r["severity"], "warning"),
            "message": {"text": f"{r['title']} against {scan['target']}.{rate} "
                                f"Evidence: {r.get('response_excerpt', '')[:200]}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": anchor},
                "region": {"startLine": 1}}}],
            "partialFingerprints": {"redlineTargetProbe/v1": fp},
            "properties": {"target": scan["target"], "verdict": r.get("verdict", ""),
                           "fire_rate": r.get("fire_rate", 0)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Redline",
                "version": __version__,
                "informationUri": "https://github.com/bryanpauze/redline",
                "rules": rules}},
            "results": results,
            "properties": {"target": scan["target"], "grade": scan["grade"],
                           "score": scan["score"]},
        }],
    }
