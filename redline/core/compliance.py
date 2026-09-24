"""Map Redline findings to the frameworks auditors and buyers ask about.

  * OWASP Top 10 for LLM Applications (2025 edition)
  * MITRE ATLAS techniques
  * NIST AI RMF 1.0 (the MEASURE/MANAGE subcategories a scan provides evidence for)

Mappings live here, keyed by probe id, so probes stay focused on attack + detect
and the mapping can be revised in one place as the frameworks evolve.
"""
from __future__ import annotations

OWASP = {
    "LLM01": "LLM01:2025 Prompt Injection",
    "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM03": "LLM03:2025 Supply Chain",
    "LLM05": "LLM05:2025 Improper Output Handling",
    "LLM06": "LLM06:2025 Excessive Agency",
    "LLM07": "LLM07:2025 System Prompt Leakage",
    "LLM10": "LLM10:2025 Unbounded Consumption",
}

ATLAS = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0010": "AI Supply Chain Compromise",
}

NIST = {
    "MEASURE 2.7": "AI system security and resilience are evaluated and documented",
    "MANAGE 2.2": "Mechanisms are in place to sustain the value of deployed AI systems",
    "GOVERN 6.1": "Policies address AI risks from third-party software and data",
}

_MAP: dict[str, dict[str, list[str]]] = {
    "INJ-01": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "INJ-02": {"owasp": ["LLM01"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "INJ-03": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "INJ-04": {"owasp": ["LLM01", "LLM06"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "INJ-05": {"owasp": ["LLM01"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "JB-01": {"owasp": ["LLM07"], "atlas": ["AML.T0056"], "nist": ["MEASURE 2.7"]},
    "JB-02": {"owasp": ["LLM07", "LLM01"], "atlas": ["AML.T0054"], "nist": ["MEASURE 2.7"]},
    "JB-03": {"owasp": ["LLM07"], "atlas": ["AML.T0054"], "nist": ["MEASURE 2.7"]},
    "LK-01": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "LK-02": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "LK-03": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "LK-04": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-01": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-02": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-03": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-04": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-05": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-06": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "OBF-07": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "OBF-08": {"owasp": ["LLM01"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "CTL-01": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-02": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-03": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-04": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-05": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-06": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-07": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-08": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-09": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-10": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-11": {"owasp": ["LLM01"], "atlas": ["AML.T0051.000"], "nist": ["MEASURE 2.7"]},
    "CTL-12": {"owasp": ["LLM01", "LLM06"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "BM-01": {"owasp": ["LLM02", "LLM07"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "BM-02": {"owasp": ["LLM02", "LLM07"], "atlas": ["AML.T0056"], "nist": ["MEASURE 2.7"]},
    "MT-01": {"owasp": ["LLM07"], "atlas": ["AML.T0054"], "nist": ["MEASURE 2.7"]},
    "MT-02": {"owasp": ["LLM01"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "MT-03": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "MT-04": {"owasp": ["LLM01", "LLM06"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "MT-05": {"owasp": ["LLM02", "LLM07"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "MT-06": {"owasp": ["LLM02", "LLM06"], "atlas": ["AML.T0057", "AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "MT-07": {"owasp": ["LLM02", "LLM01"], "atlas": ["AML.T0054"], "nist": ["MEASURE 2.7"]},
    "MT-08": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "CC-01": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "CC-02": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "CC-03": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "MCP-01": {"owasp": ["LLM03", "LLM01"], "atlas": ["AML.T0010", "AML.T0051.001"],
               "nist": ["GOVERN 6.1", "MEASURE 2.7"]},
    "MCP-02": {"owasp": ["LLM06"], "atlas": ["AML.T0053"], "nist": ["GOVERN 6.1", "MANAGE 2.2"]},
    "MCP-03": {"owasp": ["LLM01", "LLM05"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "MCP-04": {"owasp": ["LLM02", "LLM06"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "MCP-05": {"owasp": ["LLM02", "LLM06"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "AV-01": {"owasp": ["LLM10"], "atlas": [], "nist": ["MEASURE 2.7"]},
    "AV-02": {"owasp": ["LLM10"], "atlas": [], "nist": ["MEASURE 2.7"]},
    "AV-03": {"owasp": ["LLM10", "LLM05"], "atlas": [], "nist": ["MEASURE 2.7"]},
    "IOH-01": {"owasp": ["LLM05"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "IOH-02": {"owasp": ["LLM05", "LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.7"]},
    "IOH-03": {"owasp": ["LLM05"], "atlas": ["AML.T0051.001"], "nist": ["MEASURE 2.7"]},
    "PRV-01": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.10", "MEASURE 2.7"]},
    "PRV-02": {"owasp": ["LLM02"], "atlas": ["AML.T0057"], "nist": ["MEASURE 2.10"]},
    "PRV-03": {"owasp": ["LLM02", "LLM07"], "atlas": ["AML.T0057", "AML.T0056"], "nist": ["MEASURE 2.10"]},
    "MEX-01": {"owasp": ["LLM07", "LLM02"], "atlas": ["AML.T0056"], "nist": ["MEASURE 2.10", "MEASURE 2.7"]},
}


def mapping(probe_id: str) -> dict[str, list[str]]:
    """Framework references for a probe id (empty lists if unmapped)."""
    m = _MAP.get(probe_id, {})
    return {"owasp": list(m.get("owasp", [])), "atlas": list(m.get("atlas", [])),
            "nist": list(m.get("nist", []))}


def labels(probe_id: str) -> list[str]:
    """Human-readable labels, e.g. 'LLM01:2025 Prompt Injection'."""
    m = mapping(probe_id)
    return ([OWASP[k] for k in m["owasp"]]
            + [f"ATLAS {k} {ATLAS[k]}" for k in m["atlas"]]
            + [f"NIST AI RMF {k}" for k in m["nist"]])


def coverage(results: list[dict]) -> dict:
    """Roll findings up by OWASP category: which categories were tested, which failed."""
    out: dict[str, dict] = {}
    for r in results:
        for k in mapping(r["id"])["owasp"]:
            c = out.setdefault(k, {"name": OWASP[k], "tested": 0, "failed": 0})
            c["tested"] += 1
            c["failed"] += 1 if r.get("vulnerable") else 0
    return dict(sorted(out.items()))
