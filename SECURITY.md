# Security Policy

## Intended use

Prism is infrastructure for **authorized** red-team engagements and security
research only. Only point it at systems you have explicit, written permission to
test. The relays are open HTTP(S) forwarders gated by a shared token — treat that
token as a credential, rotate it between engagements, tear relays down when an
engagement ends (`prism down`), and follow each cloud provider's Terms of Service
and Acceptable Use Policy. The maintainers assume no liability for misuse.

## Reporting a vulnerability

Found a security issue in Prism itself (credential handling, the relay auth model,
the rotator, etc.)? Please report it **privately** rather than opening a public issue:

- Open a private [GitHub Security Advisory](https://github.com/TonyDAtigerr/prism/security/advisories/new)

Include reproduction steps and the affected version. We'll acknowledge the report and
work on a fix — please allow reasonable time to address it before any public disclosure.

## Supported versions

Prism is pre-1.0; only the latest release receives fixes.
