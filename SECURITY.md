# CloudOS Security Policy

CloudOS follows a security-first philosophy. This document explains how to report vulnerabilities, what is in scope, and how we handle disclosures.

## Supported Versions

- Actively maintained: main branch
- Release branches: security backports on a best-effort basis (if/when tagged releases are published)

If you are deploying CloudOS in production, pin to a tagged release and track the CHANGELOG for security-related notes.

## Reporting a Vulnerability

Please report security issues privately and responsibly.

Preferred channels:
1. GitHub Security Advisories (recommended):
   - Open a private advisory in this repo: Security > Advisories > Report a vulnerability
2. Email:
   - security@cloudos.dev (private distribution to maintainers)
   - If email is unavailable, open a minimal “security contact” issue asking for a secure reporting channel (do NOT include details).

Please include:
- Affected component(s) and file paths, if known
- Impact (RCE, privilege escalation, info disclosure, DoS, etc.)
- Reproduction steps, PoC, and environment details (OS, toolchain)
- Suggested remediation or mitigation, if any
- CVSS score (optional) and any analysis you have performed

We appreciate encrypted communication. If you need a public key, request it via the email above and we will share a PGP key fingerprint.

## Disclosure Timeline

We aim to acknowledge reports within 3 business days and provide an initial assessment within 7 business days. Remediation timelines depend on severity and complexity:
- Critical/High: fix or mitigation targeted within 14–21 days
- Medium: fix targeted within 30–45 days
- Low/Informational: fix may be bundled with a regular release

We prefer coordinated disclosure. We will work with you on mutually acceptable timelines and credit (if desired) once a patch is available and users have a reasonable upgrade window.

## Scope

In scope:
- Kernel and subsystems in this repository (kernel/*, kernel/include/*)
- Integrated tooling and scripts that affect runtime or build (scripts/*, install/*) as they relate to CloudOS security
- Documentation/security guidance issues that could lead to insecure deployment

Out of scope:
- 3rd-party dependencies unless a clear exploit is demonstrated through CloudOS integration
- Issues requiring root access and physical hardware attacks
- Social engineering, phishing, or branding issues

## Severity and Triage

We use a CVSS-like model internally to prioritize:
- Critical: remote code execution, unauthenticated privilege escalation, key material exposure
- High: authenticated privilege escalation, sandbox/container breakout
- Medium: significant information disclosure, DoS that impacts availability
- Low: misconfigurations, minor leaks, best-practice deviations

## Fixes and Releases

- Security fixes land on main and are backported to supported release branches when applicable.
- Release notes and the CHANGELOG will call out security-relevant changes.
- If a configuration change is required, documentation and migration notes will be provided.

## Safe Harbor

We will not pursue legal action for good-faith security research that adheres to:
- Avoid privacy violations and data destruction
- Do not degrade service for others (no excessive DoS)
- Make a good-faith effort to report promptly and coordinate disclosure

## Contact

- Private reports: security@cloudos.dev
- General issues: GitHub Issues
- Emergencies: use the email above with “URGENT” in the subject

Thank you for helping keep CloudOS users safe.
