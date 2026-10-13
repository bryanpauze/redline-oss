"""NIST adversarial-ML taxonomy mapping and coverage matrix.

Kept separate from compliance.py (which holds OWASP / ATLAS / AI RMF) so each framework
is one focused module. This maps Redline's probes and certificates to NIST AI 100-2e2025
(Adversarial Machine Learning: A Taxonomy and Terminology) attack IDs and to the NIST AI
600-1 Generative AI Profile risks, and computes an honest coverage matrix: which runtime-
scannable attack cells Redline exercises, which are partial, and which are out of a
black-box runtime scanner's reach (training-time / process-and-provenance controls).
"""
from __future__ import annotations

# NIST AI 100-2e2025 attack IDs -> (name, stage). objective is carried on the cell.
AML = {
    "NISTAML.014": ("Energy-latency (availability)", "inference"),
    "NISTAML.015": ("Indirect Prompt Injection", "inference"),
    "NISTAML.016": ("Indirect-PI Availability", "inference"),
    "NISTAML.017": ("Time-consuming background tasks", "inference"),
    "NISTAML.018": ("Direct Prompt Injection", "inference"),
    "NISTAML.022": ("Evasion (adversarial examples)", "inference"),
    "NISTAML.025": ("Black-box Evasion", "inference"),
    "NISTAML.027": ("Misaligned Outputs (integrity)", "inference"),
    "NISTAML.031": ("Model Extraction", "inference"),
    "NISTAML.032": ("Data Reconstruction", "inference"),
    "NISTAML.033": ("Membership Inference", "inference"),
    "NISTAML.034": ("Property Inference", "inference"),
    "NISTAML.035": ("Prompt / context Extraction", "inference"),
    "NISTAML.036": ("Leaking info from user interactions", "inference"),
    "NISTAML.037": ("Training Data Extraction", "inference"),
    "NISTAML.038": ("Data Extraction", "inference"),
    "NISTAML.039": ("Compromising connected resources", "inference"),
    "NISTAML.013": ("Data Poisoning", "training"),
    "NISTAML.023": ("Backdoor Poisoning", "training"),
    "NISTAML.024": ("Targeted Poisoning", "training"),
    "NISTAML.026": ("Model Poisoning", "training"),
    "NISTAML.051": ("Supply-chain Model Poisoning", "training"),
}

# NIST AI 600-1 GenAI Profile risks that a security scanner evidences.
GENAI_PROFILE = {
    "2.4": "Data Privacy",
    "2.8": "Information Integrity",
    "2.9": "Information Security",
    "2.12": "Value Chain and Component Integration",
}

# Redline probe CATEGORY -> the AML attack IDs it exercises (DRY; per-id overrides below).
_BY_CATEGORY = {
    "injection": ["NISTAML.018"],
    "control-token": ["NISTAML.018"],
    "jailbreak": ["NISTAML.018", "NISTAML.035"],
    "leakage": ["NISTAML.038", "NISTAML.037"],
    "obfuscation": ["NISTAML.018"],
    "multi-turn": ["NISTAML.018", "NISTAML.015", "NISTAML.039"],
    "covert-channel": ["NISTAML.036", "NISTAML.038"],
    "availability": ["NISTAML.016", "NISTAML.017", "NISTAML.014"],
    "output-handling": ["NISTAML.027", "NISTAML.039"],
    "privacy": ["NISTAML.032", "NISTAML.033", "NISTAML.037", "NISTAML.035"],
}
# per-id refinements where an id is more specific than its category
_BY_ID = {
    "JB-01": ["NISTAML.035", "NISTAML.018"],
    "MT-06": ["NISTAML.015", "NISTAML.039", "NISTAML.027"],
    "IOH-02": ["NISTAML.027", "NISTAML.039", "NISTAML.036"],
    "PRV-01": ["NISTAML.032", "NISTAML.037"],
    "PRV-02": ["NISTAML.032", "NISTAML.037"],
    "PRV-03": ["NISTAML.035", "NISTAML.037"],
    "MEX-01": ["NISTAML.031"],
}
# MCP probes are indirect-PI / tool poisoning / connected-resource compromise
_MCP = ["NISTAML.015", "NISTAML.039"]

# Certificates and engines cover architectural / agent cells directly.
CERT_COVERAGE = {
    "exfil-cert": ["NISTAML.039", "NISTAML.015"],
    "covert": ["NISTAML.036"],
}


def aml_for(probe_id: str, category: str) -> list[str]:
    if probe_id in _BY_ID:
        return _BY_ID[probe_id]
    if probe_id.startswith("MCP-"):
        return _MCP
    return _BY_CATEGORY.get(category, [])


def _covered_ids(probes) -> set:
    ids = set()
    for p in probes:
        ids.update(aml_for(p.id, p.category))
    for cov in CERT_COVERAGE.values():
        ids.update(cov)
    return ids


# runtime cells a black-box scanner cannot fully exercise, with the honest reason.
_PARTIAL = {
    "NISTAML.014": "latency/output-size signal only, not a full energy-latency attack",
    "NISTAML.037": "canary-based extraction only; true memorization needs the model's own training data",
    "NISTAML.032": "planted-record reconstruction; not arbitrary training-record recovery",
    "NISTAML.031": "model-info disclosure surface only, not full parameter theft",
}
_OUT_OF_SCOPE = {
    "NISTAML.022": "PredAI classifier evasion (image/tabular), not the LLM domain Redline targets",
    "NISTAML.025": "PredAI black-box evasion, out of the LLM domain",
    "NISTAML.033": "membership inference needs training-set access / statistical query volume",
    "NISTAML.034": "property inference needs distributional query volume, not black-box scannable",
    "NISTAML.013": "training-time poisoning: process/provenance control (see redline inventory)",
    "NISTAML.023": "training-time backdoor: process/provenance control",
    "NISTAML.024": "training-time poisoning: process/provenance control",
    "NISTAML.026": "training-time model poisoning: process/provenance control",
    "NISTAML.051": "supply-chain model poisoning: provenance control (partially via redline inventory)",
}


def coverage(probes) -> dict:
    """A per-cell coverage matrix over the NIST AML taxonomy."""
    covered = _covered_ids(probes)
    cells = []
    counts = {"covered": 0, "partial": 0, "out_of_scope": 0}
    for aml_id, (name, stage) in sorted(AML.items()):
        # curated overrides win over a probe mapping, so a cell is never overclaimed
        if aml_id in _OUT_OF_SCOPE:
            status, note = "out_of_scope", _OUT_OF_SCOPE[aml_id]
        elif aml_id in _PARTIAL:
            status, note = "partial", _PARTIAL[aml_id]
        elif aml_id in covered:
            status, note = "covered", ""
        else:
            status, note = "gap", ""
        counts[status] = counts.get(status, 0) + 1
        cells.append({"id": aml_id, "name": name, "stage": stage,
                      "status": status, "note": note})
    return {"cells": cells, "counts": counts,
            "genai_profile": GENAI_PROFILE,
            "runtime_covered_or_partial": counts["covered"] + counts["partial"]}
