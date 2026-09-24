"""Signing utility for Redline certificates.

Attaches an HMAC-SHA256 signature over a document's canonical bytes, so a certificate
such as an exfiltration-path certificate is tamper-evident: anyone with the signing key
can recompute the signature and detect any change. The key comes from the
REDLINE_AUDIT_KEY environment variable. With no key set, documents are emitted unsigned
and say so on the signature block.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time


def _signing_key() -> bytes | None:
    k = os.environ.get("REDLINE_AUDIT_KEY", "")
    return k.encode("utf-8") if k else None


def _canonical(doc: dict) -> bytes:
    # sorted keys, compact separators, over the document minus its own signature block
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_document(doc: dict) -> dict:
    """Attach a signature block over the document's canonical bytes (any dict)."""
    key = _signing_key()
    doc["signature"] = {
        "alg": "HMAC-SHA256",
        "signed": bool(key),
        "key_version": "v1" if key else None,
        "value": (hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest() if key else None),
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
