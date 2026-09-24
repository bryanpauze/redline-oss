"""Signed scan-evidence bundles: portable, tamper-evident proof that a scan ran.

Ported in spirit from control-plane's control_plane/evidence/service.py, reusing
the SAME canonical-bytes + HMAC recipe as redline/core/audit.py (so one signing
key covers both). A bundle summarizes one scan (target, grade, findings by
severity, probe/pack versions, confidence, framework coverage, baseline delta)
plus the audit-chain hash range that backs it, and signs the whole thing. A
customer hands the bundle to an auditor or a cyber-insurer; anyone can verify it
with verify_bundle() and the public description of the recipe, without Redline.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone

from .. import __version__

BUNDLE_VERSION = "v1"


def _signing_key() -> bytes | None:
    k = os.environ.get("REDLINE_AUDIT_KEY", "")
    return k.encode("utf-8") if k else None


def _canonical(bundle: dict) -> bytes:
    # Same recipe as the audit chain: sorted keys, compact separators, over the
    # document MINUS its own signature block.
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_document(doc: dict) -> dict:
    """Attach a signature block over the document's canonical bytes (any dict).
    Reused by evidence bundles and certificates so one key covers both."""
    key = _signing_key()
    canonical = _canonical(doc)
    doc["signature"] = {
        "alg": "HMAC-SHA256",
        "signed": bool(key),
        "key_version": "v1" if key else None,
        "value": (hmac.new(key, canonical, hashlib.sha256).hexdigest() if key else None),
        "signed_at": time.time(),
    }
    return doc


def verify_document(doc: dict, key_hex: str | None = None) -> dict:
    """Recompute the signature over any signed document. Returns {ok, reason}."""
    sig = doc.get("signature") or {}
    key = (key_hex or os.environ.get("REDLINE_AUDIT_KEY") or "").encode("utf-8")
    if not sig.get("signed"):
        return {"ok": False, "reason": "document is unsigned"}
    if not key:
        return {"ok": False, "reason": "no key provided to verify with"}
    expect = hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expect, sig.get("value") or ""):
        return {"ok": True, "reason": "signature valid"}
    return {"ok": False, "reason": "signature mismatch (document altered or wrong key)"}


def _severity_counts(results: list[dict]) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        if r.get("vulnerable"):
            out[r["severity"]] = out.get(r["severity"], 0) + 1
    return out


def build_bundle(scan: dict, *, controls: list[str] | None = None,
                 baseline_delta: dict | None = None,
                 audit_range: dict | None = None,
                 subject: str | None = None) -> dict:
    """Assemble and sign an evidence bundle from a ScanResult.to_dict() `scan`.

    `controls`      operator-declared control tags (e.g. ["soc2-cc6.1", "eu-ai-act-art-15"])
    `baseline_delta` output of core.baseline.diff, if a baseline was used
    `audit_range`   {"first_event": id, "last_event": id, "first_hash", "last_hash"}
                    linking this bundle to the tamper-evident audit chain
    """
    results = scan.get("results", [])
    owasp = sorted({k for r in results for k in (r.get("compliance") or {}).get("owasp", [])
                    if r.get("vulnerable")})
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "tool": {"name": "Redline", "version": __version__},
        "generated": datetime.now(timezone.utc).isoformat(),
        "subject": subject or scan.get("target"),
        "scan": {
            "target": scan.get("target"),
            "started": scan.get("started"),
            "grade": scan.get("grade"),
            "score": scan.get("score"),
            "trials": scan.get("trials", 1),
            "validator": scan.get("validator", "none"),
            "probes": scan.get("summary", {}).get("probes"),
            "vulnerable": scan.get("summary", {}).get("vulnerable"),
            "confirmed": scan.get("summary", {}).get("confirmed"),
            "inconclusive": scan.get("summary", {}).get("inconclusive"),
        },
        "findings": [
            {"id": r["id"], "severity": r["severity"], "verdict": r.get("verdict"),
             "fire_rate": r.get("fire_rate"), "ci": [r.get("ci_low"), r.get("ci_high")],
             "compliance": r.get("compliance", {})}
            for r in results if r.get("vulnerable")
        ],
        "severity_counts": _severity_counts(results),
        "owasp_failed": owasp,
        "controls": sorted(controls or []),
        "baseline_delta": baseline_delta,
        "audit_range": audit_range,
        # a self-contained integrity anchor over the full scan result
        "scan_digest": "sha256:" + hashlib.sha256(
            json.dumps(scan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
    return sign_document(bundle)


def verify_bundle(bundle: dict, key_hex: str | None = None) -> dict:
    """Recompute the signature over the canonical bytes. Returns {ok, reason}."""
    return verify_document(bundle, key_hex)
