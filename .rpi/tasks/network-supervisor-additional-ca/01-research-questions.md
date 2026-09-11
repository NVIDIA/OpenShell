---
rpi_task: network-supervisor-additional-ca
workflow: rpi
phase: research
document_status: draft
updated: 2026-09-10T22:13:52Z
---

# Research questions

## Current behavior and data flow

1. **High priority:** Where is the gateway/network-supervisor configuration defined and parsed, and which existing global sections are candidates for a non-driver-specific CA setting? Evidence needed: configuration structs, TOML/YAML schemas, defaults, and parsing tests with file/line references.
2. **High priority:** Where does the network supervisor build TLS clients or root stores for sandbox network destinations? Evidence needed: initialization and request/data-flow code, including how errors are surfaced.
3. **High priority:** How do Docker, Podman, Kubernetes, VM, and any other supported compute drivers start or configure the network supervisor? Evidence needed: shared versus driver-specific call paths and configuration propagation with file/line references.
4. What does the current system do when a destination presents a self-signed or otherwise privately rooted certificate, and are there existing CA-loading helpers or related settings?

## Constraints and compatibility

5. **High priority:** Which trust roots are currently used, and can additional roots be added without replacing system/public roots? Evidence needed: root-store construction and tests.
6. What are the existing startup, reload, filesystem, permission, and error-reporting conventions for certificate material and global configuration?
7. What security/operational risks arise from configurable CA material, and what validation or logging constraints must be retained (including avoiding secret/certificate-content logging)?

## Design choices to resolve later

8. Should the supported configuration accept inline PEM, one or more file paths, or both? Identify repository conventions and operational trade-offs without selecting an implementation in research.
9. At what lifecycle point should additional CA material be loaded, and is runtime reload required by current configuration behavior?
10. What configuration naming and placement will clearly remain outside compute-driver sections and be consistent with the existing gateway configuration model?

## Verification

11. **High priority:** What shared unit/integration test seams can verify additional CA parsing, root-store construction, and TLS success/failure, and what driver matrix or contract tests prove all compute drivers consume the shared configuration?
12. Which architecture, gateway-config, and driver documentation pages must be updated for the user-visible configuration?

## External references

13. Are current Rust TLS/root-certificate library APIs or platform trust-store behavior relevant to the implementation? Consult external documentation only if repository evidence leaves an API or compatibility question unresolved.
