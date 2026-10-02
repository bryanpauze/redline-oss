# Security Policy

Redline is a security scanner, so we hold its own code to the standard it checks
for. Thank you for helping keep it and its users safe.

## Supported versions

Fixes land on `main` and ship in the next tagged release. Please test against the
latest release or `main` before reporting.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
go to the repository's **Security** tab → **Report a vulnerability**. This opens a
private advisory visible only to the maintainers.

Please include:

- the affected version or commit,
- a description of the issue and its impact,
- the minimal steps or a proof-of-concept to reproduce it.

We aim to acknowledge a report within a few days and to agree a disclosure
timeline with you. We'll credit you in the advisory unless you'd rather stay
anonymous.

## Scope

In scope: the `redline` package and its command-line interface.

Out of scope (these are intentional and documented, not vulnerabilities):

- The bundled **vulnerable MCP fixture** (`redline/fixtures/`) is deliberately
  insecure — it is a scan target used by the tests and demo.
- **Covert-channel probes** intentionally embed zero-width and homoglyph
  characters; that is the behaviour they test for.
- Scanning a target you do not own or have permission to test is on you, not a
  flaw in the tool. Only point Redline at systems you are authorized to assess.

## Running a target that executes code

`redline scan --target mcp --command ...` and `redline exfil-cert --mcp-command ...`
launch a local process (the MCP server you point them at). Treat that command the
way you would any other: only run MCP servers you trust.
