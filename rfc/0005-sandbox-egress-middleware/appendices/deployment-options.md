# Appendix: Deployment Options

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

This appendix records why the first version uses an externally managed service endpoint and what deployment modes remain open for later evaluation. Supporting multiple deployment modes is an explicit non-goal of the main RFC; this document preserves the analysis so the decision is not lost.

## Decision: an externally managed service endpoint

The first version routes selected egress to a middleware service reachable over the network, operated by the user. OpenShell holds only the connection details (endpoint, transport, and any auth material) and the request/response contract. It does not package, deploy, or manage the lifecycle of the middleware.

Rationale:

- **Minimal new infrastructure.** OpenShell does not have to build image packaging, process supervision, or a runtime for the middleware. The first iteration can focus on the contract, failure behavior, and the supervisor integration.
- **Portable across compute drivers.** A network endpoint is reachable from a sandbox regardless of whether it runs as a container, a VM, or a local process. A Unix socket would not cross the VM boundary, so a network endpoint is the portable choice that works the same way everywhere.
- **Independent iteration.** The middleware is an integration point with another team. An external service lets them deploy, scale, and update it on their own cadence, without coupling releases to OpenShell.
- **Heavy compute friendly.** Detection work may need GPUs or significant memory. An external service can live wherever those resources are, and can be scaled separately from the sandbox fleet.

Tradeoffs:

- The middleware is a trusted component with raw access to request content. As a standalone network service it sits outside OpenShell's isolation boundary, typically with its own connectivity and credentials. The main RFC calls out trust in the middleware as a non-goal; this deployment shape leans on that assumption.
- The operator is responsible for deploying, securing, and maintaining the service.

## Future options

These are recorded as directions, not committed designs.

### Middleware running inside its own sandbox

Package the middleware as a container image and run it inside an OpenShell sandbox, then route egress content to it. The middleware would inherit sandbox isolation: policy-enforced egress, filesystem and syscall constraints, and no open internet access unless explicitly granted.

This is the most direct answer to the trust concern. Instead of trusting the middleware not to exfiltrate the content it inspects, the operator constrains it the same way any other sandbox is constrained. A PII redactor with no network egress cannot leak what it sees, even if the image is compromised.

This option depends on sandbox-to-sandbox communication ([#1049](https://github.com/NVIDIA/OpenShell/issues/1049)), which is not available yet. When it lands, this becomes the most attractive shape for untrusted or third-party middleware.

### WASM middleware

Run the middleware as a WebAssembly module loaded by the supervisor, in-process with the proxy. This offers strong isolation with low latency and no separate service to operate, at the cost of a constrained runtime (limited libraries, no GPU access). It is a good fit for lightweight checks such as regex-based scanning, and a poor fit for model-backed detection.

### OpenShell-managed image or sidecar

OpenShell pulls and runs the middleware image itself, for example as a sidecar of the sandbox. This improves the user experience by removing the need to operate a separate central service, and keeps processing local. In exchange, OpenShell takes on lifecycle management and resource concerns, and on its own it does not provide the isolation benefit of the sandboxed option above unless combined with policy enforcement.
