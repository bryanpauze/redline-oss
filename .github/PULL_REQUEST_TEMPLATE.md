## What this changes

## Checklist
- [ ] `ruff check .`, `mypy redline`, `bandit -r redline -c pyproject.toml -q`, `detect-secrets-hook --baseline .secrets.baseline $(git ls-files)` and `pytest -q --cov=redline --cov-fail-under=66` pass locally
- [ ] New behaviour has a test (new probes: a golden case and a framework mapping)
- [ ] No new runtime dependencies
- [ ] CHANGELOG.md updated under `[Unreleased]` for user-visible changes
