"""Small statistics helpers for multi-trial probing.

A single probe run is one Bernoulli trial: it fired or it didn't. Running a probe
N times gives a fire rate, and the Wilson score interval is the honest way to put
a confidence band on that rate for small N (far better than normal approximation,
and well-behaved at 0% and 100%).
"""
from __future__ import annotations

import math


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% (z=1.96) Wilson score interval for k successes in n trials."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def fmt_rate(k: int, n: int) -> str:
    if n <= 0:
        return "n/a"
    return f"{100 * k / n:.0f}% ({k}/{n})"
