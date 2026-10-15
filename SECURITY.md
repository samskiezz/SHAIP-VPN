# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Email the maintainers privately with:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The version / commit affected.

## Our commitment

- Acknowledge your report within 72 hours.
- Provide a fix or mitigation plan for critical issues within 30 days.
- Credit you in the release notes unless you prefer anonymity.
- No legal action against good-faith security research.

## Scope

In scope: the Rust core (`client/`, `server/`), the Go control plane
(`control-plane/`), the web UI (`web-ui/`), the wire protocol, the
cryptographic construction, and the deployment scaffolding in this repo.

Out of scope: volumetric denial of service, social engineering, physical
attacks, and issues in third-party dependencies (report those upstream).

## Pre-audit status

This is pre-audit software. It has **not** had an independent external
security review. Do not place real high-risk traffic on it until it has.
