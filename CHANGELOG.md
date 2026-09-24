# Changelog

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
