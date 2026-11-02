# Security Policy

## Reporting a vulnerability

Report OpenShell vulnerabilities through [GitHub's private reporting form](https://github.com/NVIDIA/OpenShell/security/advisories/new). Submitting a report does not publish an advisory. Do not disclose vulnerabilities in public issues, discussions, or pull requests.

Every report must use the [advisory template](.agents/skills/create-security-advisory/assets/advisory-template.md). Keep its core headings and include:

- Affected component and version, commit, or image digest.
- Description, impact, and prerequisites for exploitation.
- Reproduction steps and observed results, or concrete code evidence of the attack path.
- Relevant deployment and policy configuration, with secrets and personal information removed.
- Known mitigations, existing CVE identifiers, or disclosure deadlines, if any.

The [OpenShell maintainers](https://github.com/NVIDIA/OpenShell/blob/main/MAINTAINERS.md) acknowledge and assess reports, request additional details when needed, and coordinate remediation. Follow-up discussions, decisions, and progress updates remain in the private report or advisory thread.

### Report quality and agent skills

AI tools may assist investigation and drafting under our [AI usage guidelines](CONTRIBUTING.md#ai-usage). A human reporter must review the report, verify its accuracy, and be able to explain the attack scenario and supporting evidence. Distinguish reproduced behavior, code inspection, and unverified claims. Raw scanner output, agent transcripts, or speculative vulnerability lists alone are not sufficient.

Reports that do not follow the template or lack concrete reproduction or code evidence will be returned for revision before technical triage. Identify missing information explicitly; a root cause, CVSS/CWE classification, or proposed fix is not required.

The agent skills are optional helpers: with a source checkout, [create-security-advisory](.agents/skills/create-security-advisory/SKILL.md) helps prepare a report; maintainers can use [review-security-issue](.agents/skills/review-security-issue/SKILL.md) for assessment. Submit reports through the private form above.

## Coordinated disclosure

The maintainers and reporter agree on a disclosure date after assessment. Keep details confidential until that date; any extension is discussed with the reporter. Access is limited to people involved in investigation, remediation, or coordination.

We aim to publish an advisory with a fix or mitigation. Active exploitation or details already being public may require earlier notification. Advisories explain when a fix is unavailable and identify known mitigations.

## Supported versions

In line with [RFC 0014](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0014-release-stability/README.md#maintenance-and-backports), security support applies to the newest patch of each maintained line:

| Release line | Security updates |
| --- | --- |
| Latest stable minor (N) | New patch releases. |
| Previous stable minor (N-1) | Backports when affected. |
| Older minor releases | Upgrade to a maintained line. |

Users of older patches must upgrade to the current maintenance patch. Security fixes may ship outside the regular release cadence.

Pre-release and development builds are for testing. Reports affecting them or older releases are still welcome.

## Security bulletins

Published [GitHub Security Advisories (GHSA)](https://github.com/NVIDIA/OpenShell/security/advisories) describe impact, affected and fixed versions, and mitigation or upgrade instructions.
