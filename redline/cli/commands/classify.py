"""`shadow-text`: heuristic AI-authorship signal for a text file."""
from __future__ import annotations


def cmd_shadow_text(a) -> int:
    from ...core.shadow_ai import classify_text
    with open(a.path) as f:
        r = classify_text(f.read())
    print(f"  AI-authored likelihood: {r['score']:.2f}  ({r['label']})")
    return 0


def register(sub) -> None:
    st = sub.add_parser("shadow-text", help="heuristic: is text likely AI-authored?")
    st.add_argument("path")
    st.set_defaults(func=cmd_shadow_text)
