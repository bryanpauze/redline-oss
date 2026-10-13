# Changelog

## [0.2.0] - 2026-10-13
Public-readiness review: detection precision, soundness of `exfil-cert`, and hardening
against hostile targets and MCP servers.

### Fixed
- Detection: probes no longer fire on a target that only echoes the prompt back, and the
  override-token detector no longer fires on a refusal that quotes the token.
- `--judge`: a judge that errors now abstains instead of silently clearing every finding.
- Grading: a scan where half or more of the probes errored is inconclusive (`?`, exit 2)
  instead of grading the reachable half as clean. `fingerprint` reports `INCONCLUSIVE`
  (exit 2) instead of "strongly defended" for an unreachable target.
- `exfil-cert`: snake_case/camelCase tool names are now labeled, tools the labeler can't
  place are treated as capable of every role, and private data in context is assumed by
  default, closing cases where a leaky tool graph was certified safe. Tools can declare
  `redline_roles` to correct over-blocking. The CLI now says whether the certificate is
  actually signed (`REDLINE_AUDIT_KEY`).
- Covert-channel scoring no longer credits the secret's public `sk-live-` prefix.
- `--polymorph N` now grades reliability (`confirmed`/`intermittent`), like `--trials`.
- `scan --target mcp --url` uses the HTTP transport instead of trying to execute the URL.
- SARIF from the CLI always carries a location URI (`--sarif-anchor` defaults to
  `redline.target`).
- Deployed mode: fewer false positives on refusals and placeholder text, and real secrets
  it finds are masked in HTML/JSON/SARIF reports instead of republished.
- JSON-style tool calls are checked for secrets in their arguments.
- `--host host:port` without a scheme works for the serving-stack presets.
- Clean errors (not tracebacks) for an unknown profile, a malformed baseline, malformed
  certificates, and bad target URLs; report paths create their parent directory.

### Security
- HTTP targets accept only http/https URLs and read responses with a size cap; the
  obfuscation decoder bounds its work on very large replies.
- MCP: hostile server output can no longer crash the scanner or orphan the server
  process; MCP-05 never invokes a tool that isn't provably read-only; SSE reads are
  bounded; `inventory` reads only regular files and shell-quotes suggested commands.

### Added
- Issue/PR templates, Dependabot, a code of conduct, and a release workflow that reuses CI.

## [0.1.0] - 2026-09-23
First public release of the open-source community edition.

### Added
- 55 chat probes across ten classes (injection, control-token, jailbreak, leakage,
  obfuscation, multi-turn, covert-channel, availability, output-handling, privacy) plus
  five MCP-server probes, with canary-based deterministic detection and decode-then-match.
- Target adapters: mock, Ollama, OpenAI, Anthropic, generic HTTP, and named open-weight
  serving stacks (vLLM, llama.cpp, TGI, LM Studio, Together, Groq, OpenRouter, Fireworks,
  DeepInfra) plus a raw completion endpoint with a selectable prompt template.
- `redline exfil-cert`: a signed, sound exfiltration-path certificate over an MCP or
  tool-list capability graph.
- `redline coverage`: NIST AI 100-2e2025 adversarial-ML coverage matrix.
- HTML / JSON / SARIF reports, baseline diffing, guardrail fingerprinting, AI-BOM
  inventory (CycloneDX), covert-channel measurement, shadow-AI egress-log analysis,
  scan profiles with golden detector-regression sets, and a GitHub Action.
