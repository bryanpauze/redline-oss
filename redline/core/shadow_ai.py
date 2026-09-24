"""Behavioral shadow-AI classifier: is a piece of text likely AI-authored?

Ported in spirit from control-plane's control_plane/shadow_ai/classifiers.py. This
is a corroborating signal, not proof. The egress-log analyzer is the strong,
network-level shadow-AI detector; this is a cheap content-level heuristic for when
you only have text (a document, a commit message, a support reply) and want a hint
that an ungoverned model produced it. Stdlib only, and honestly weak: it flags
statistical tells, so treat a hit as "worth a look," never as a verdict.
"""
from __future__ import annotations

import re

# words over-represented in LLM output relative to human writing (well-documented tells)
_OVERREPRESENTED = {
    "delve", "tapestry", "leverage", "leveraging", "seamless", "seamlessly",
    "robust", "intricate", "multifaceted", "nuanced", "underscore", "underscores",
    "furthermore", "moreover", "additionally", "notably", "crucially",
    "realm", "landscape", "testament", "pivotal", "paramount", "showcasing",
    "elevate", "unlock", "harness", "holistic", "synergy", "vibrant",
    "meticulous", "meticulously", "boasts", "navigating", "empower", "empowers",
}
_AI_SELF = re.compile(
    r"\b(as an ai( language model)?|i'?m (an|a) (ai|language model)|"
    r"i cannot|i (do not|don't) have (personal|the ability)|"
    r"as a large language model|i'?m unable to)\b", re.I)
_HEDGE = re.compile(
    r"\b(it'?s (important|worth) (to note|noting)|keep in mind|"
    r"there are (a few|several) (things|factors)|in conclusion|"
    r"overall,|to summarize|in summary)\b", re.I)
_NAME_HINT = re.compile(r"\b(gpt-?[0-9]|chatgpt|claude|gemini|copilot|llama|mistral)\b", re.I)


def _words(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z']+", text.lower())


def classify_text(text: str) -> dict:
    """Score text for AI authorship. Returns {label, score, signals}."""
    text = text or ""
    words = _words(text)
    n = max(1, len(words))
    over = [w for w in words if w in _OVERREPRESENTED]
    over_rate = len(over) / n
    emdash = text.count("—")
    emdash_density = emdash / max(1, text.count("\n") + 1)
    signals = {
        "overrepresented_words": sorted(set(over)),
        "overrepresented_rate": round(over_rate, 4),
        "emdash_count": emdash,
        "emdash_density_per_line": round(emdash_density, 2),
        "ai_self_reference": bool(_AI_SELF.search(text)),
        "hedging_scaffold": bool(_HEDGE.search(text)),
        "model_name_mention": bool(_NAME_HINT.search(text)),
    }
    # weighted score; self-reference is near-conclusive, the rest are soft tells
    score = 0.0
    if signals["ai_self_reference"]:
        score += 0.6
    score += min(0.3, over_rate * 40)          # ~0.3 by ~0.75% overrepresented
    if len(set(over)) >= 3:
        score += 0.15
    if emdash >= 3 and emdash_density >= 2:
        score += 0.1
    if signals["hedging_scaffold"]:
        score += 0.1
    if signals["model_name_mention"]:
        score += 0.05
    score = round(min(1.0, score), 3)
    label = ("likely_ai" if score >= 0.6 else "possibly_ai" if score >= 0.35 else "human_or_unknown")
    return {"label": label, "score": score, "signals": signals,
            "note": "heuristic signal only; corroborate with egress-scan, never a verdict"}


def scan_texts(items: list[dict], key: str = "text") -> dict:
    """Classify a batch. Each item is a dict with a text field (and optional 'source')."""
    flagged = []
    for it in items:
        r = classify_text(it.get(key, ""))
        if r["label"] != "human_or_unknown":
            flagged.append({"source": it.get("source"), **r})
    return {"scanned": len(items), "flagged": len(flagged),
            "flagged_items": sorted(flagged, key=lambda x: -x["score"])}
