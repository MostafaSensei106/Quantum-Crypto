# Security policy

Quantum-Crypto 0.0.3 is a Dev Preview, not independently audited or FIPS validated.
Only the current development version receives fixes; older formats have known
security limitations. Read [threat model](doc/threat-model.md) and
[migration guidance](doc/migration-0.0.3.md) before upgrading.

## Reporting a vulnerability

Email **mostafasensei106@gmail.com** (the maintainer contact already listed by
this project). Include affected versions/commit, impact, a minimal reproduction
and proposed mitigations if available. Do not include production private keys,
seeds or other people's sensitive data. Please report privately before opening
an issue containing exploit details.

The maintainer can coordinate reproduction, remediation and disclosure with the
reporter. No response-time SLA, bug bounty, encrypted mailbox or guaranteed
remediation date is currently offered. Coordinate publication timing directly;
this policy does not impose a legal restriction on research.

Known limitations and verification gaps are tracked in
[security verification](doc/security-verification.md). Passing tests or dependency
scans does not constitute a security audit.
