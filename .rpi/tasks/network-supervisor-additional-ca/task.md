---
rpi_task: network-supervisor-additional-ca
workflow: rpi
document_status: active
---

# Additional CA materials for the network supervisor

## Request

Add a way to configure additional `ca.crt` materials for the network supervisor so that connections from sandboxes to network destinations that use self-signed certificates can be trusted. This should work for all compute drivers. The configuration should not be in the compute driver section.

## Desired outcome

Operators can configure additional certificate-authority material in a shared, non-compute-driver configuration location. The network supervisor uses that material as additional trust for sandbox egress TLS connections while retaining the existing behavior for destinations trusted by the default CA set, consistently across every compute driver.

## Acceptance criteria

- [ ] A documented configuration mechanism accepts one or more additional CA certificate materials for the network supervisor outside the compute-driver configuration sections.
- [ ] The configured CA material is available to the network supervisor for sandbox outbound TLS verification, allowing destinations signed by the configured self-signed CA to be trusted.
- [ ] The additional trust behavior is shared by all supported compute drivers rather than implemented only in one driver.
- [ ] Default/public CA trust and existing configurations remain unchanged when no additional CA material is configured.
- [ ] Invalid or unusable CA configuration fails or reports an actionable error without silently weakening certificate verification.
- [ ] Automated tests cover configuration, propagation/initialization, and TLS trust behavior at the appropriate shared and driver boundaries.
- [ ] Relevant architecture and user-facing configuration documentation are updated.

## Constraints and non-goals

- The configuration must not live in a compute-driver-specific section.
- Additional CAs must augment, not replace, the existing trusted CA behavior unless an explicitly approved design says otherwise.
- The behavior must apply uniformly to all compute drivers through the shared network-supervisor path.
- Do not include real certificates, credentials, or other sensitive material in task artifacts or source control.
- Preserve backward compatibility for installations that do not configure additional CA material.
- Do not broaden the change into general TLS policy changes unrelated to trusting configured additional CAs.

## Relevant links

- None supplied.

## Open questions

- What existing global configuration section and representation best fit additional CA material (inline PEM, file path, or both)?
- Where is the network supervisor TLS trust store constructed, and how does configuration reach it for each compute driver?
- Are configuration reloads expected, or is CA material read only during gateway/sandbox startup?
- What error, permissions, and certificate-chain handling rules already exist and should be preserved?
- Which shared integration and driver-specific tests can prove uniform behavior without duplicating the same TLS test for every driver?
