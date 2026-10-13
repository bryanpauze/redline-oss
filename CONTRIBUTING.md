# Contributing to Redline (OSS)

Thanks for your interest. Redline is the community security scanner for LLMs,
agents, and MCP servers. Contributions — probes, detectors, fixes, docs — are
welcome.

## Ground rules

- **Standard library only.** The `redline` package has no runtime dependencies,
  on purpose: it must run anywhere with a stock Python. Don't add third-party
  runtime deps. (`anthropic` is an optional extra used only for the Anthropic
  target.)
- **Deterministic by default.** Detectors and the probe suite must give the same
  answer for the same input. Anything that samples a model is opt-in.
- **Python 3.10–3.13.**
- **Apache-2.0.** By contributing you agree your contribution is licensed under
  the repository's [LICENSE](LICENSE).

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a PR

Run the same gates CI runs — all of them must pass:

```bash
ruff check .                                   # lint + import order
mypy redline                                   # types
bandit -r redline -c pyproject.toml -q         # SAST
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)   # no new secrets
pytest -q --cov=redline --cov-fail-under=66    # tests + coverage floor
```

New code should come with tests, and coverage must stay at or above the floor.
If you add a legitimate fixture secret, re-baseline with
`detect-secrets scan > .secrets.baseline` and say so in the PR.

## Adding a probe

Probes live in `redline/probes/` and self-register. A probe is a `Probe(...)`
with an `id`, `category`, `severity`, `title`, a `build(ctx)` that returns the
chat messages to send, a `detect(...)` that decides whether the target failed,
and a `remediation`. Add a golden case so the detector's behaviour is pinned
against regressions, and a framework mapping (OWASP LLM / MITRE ATLAS / NIST) so
`redline probes` and the coverage matrix stay complete — the test suite checks
that every probe is mapped.

## Reporting bugs and security issues

- Ordinary bugs: open a GitHub issue with repro steps.
- **Security vulnerabilities: do not open a public issue** — follow
  [SECURITY.md](SECURITY.md).
