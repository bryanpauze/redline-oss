"""Redline (OSS) command-line interface.

Thin registry: redline/cli/commands/*.py each register their own subparser and
handler, and app.main() dispatches to the selected handler. The console entry
point (pyproject: redline = "redline.cli:main") imports main here.
"""
from __future__ import annotations

from .app import main

__all__ = ["main"]
