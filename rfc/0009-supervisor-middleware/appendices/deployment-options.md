# Appendix: Deployment Options

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

This appendix records why the first version of supervisor middleware supports in-process built-ins plus externally managed network service endpoints, and what deployment modes remain open for later evaluation. Supporting every deployment mode is an explicit non-goal of the main RFC; this document preserves the analysis so the decision is not lost.

## Decision: built-ins and externally managed service endpoints

The first version runs first-party built-ins inside the supervisor and routes selected external evaluations to operator-run services reachable by the gateway and supervisors. Built-ins need no registration or network transport. For external services, OpenShell holds only the connection details, body limit, transport settings, and operation-specific evaluation/result contract. It does not package, deploy, or manage the service lifecycle.

Rationale:

- **Minimal new infrastructure.** Built-ins reuse the supervisor process. External middleware does not require OpenShell to build image packaging, process supervision, or a new runtime. The first iteration can focus on the contract, failure behavior, and supervisor integration.
- **Portable across compute drivers.** A network endpoint is reachable from supervisors regardless of whether the sandbox workload runs as a container, a VM, or a local process. Other endpoint shapes do not have a universal way to be shared with every relevant supervisor environment yet, so a network endpoint is the portable choice that works the same way everywhere.
- **Independent iteration.** The middleware is an integration point with another team. An external service lets them deploy, scale, and update it on their own cadence, without coupling releases to OpenShell.
- **Heavy compute friendly.** Detection work may need GPUs or significant memory. An external service can live wherever those resources are, and can be scaled separately from the sandbox fleet.

Tradeoffs:

- The middleware is a trusted component with raw access to request content. As a standalone network service it sits outside OpenShell's isolation boundary, typically with its own connectivity and credentials. The main RFC calls out trust in the middleware as a non-goal; this deployment shape leans on that assumption.
- The operator is responsible for deploying, securing, and maintaining the service.

## Future options

These are recorded as directions, not committed designs. They have no committed timeline in this RFC; sequencing depends on the initial external-service implementation, adoption feedback, and the availability of supporting primitives such as sandbox-to-sandbox communication.

### Middleware running inside its own sandbox

Package the middleware as a container image and run it inside an OpenShell sandbox, then route egress content to it. The middleware would inherit sandbox isolation: policy-enforced egress, filesystem and syscall constraints, and no open internet access unless explicitly granted.

This is the most direct answer to the trust concern. Instead of trusting the middleware not to exfiltrate the content it inspects, the operator constrains it the same way any other sandbox is constrained. A PII redactor with no network egress cannot leak what it sees, even if the image is compromised.

This option depends on sandbox-to-sandbox communication ([#1049](https://github.com/NVIDIA/OpenShell/issues/1049)), which is not available yet. When it lands, this becomes the most attractive shape for untrusted or third-party middleware.

### WASM middleware

Run the middleware as a WebAssembly module loaded by the supervisor, in-process with the proxy. This offers strong isolation with low latency and no separate service to operate, at the cost of a constrained runtime (limited libraries, no GPU access). It is a good fit for lightweight checks such as regex-based scanning, and a poor fit for model-backed detection.

### OpenShell-managed image or sidecar

OpenShell pulls and runs the middleware image itself, for example as a sidecar of the sandbox. This improves the user experience by removing the need to operate a separate central service, and keeps processing local. In exchange, OpenShell takes on lifecycle management and resource concerns, and on its own it does not provide the isolation benefit of the sandboxed option above unless combined with policy enforcement.
