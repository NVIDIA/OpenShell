---
name: debug-inference
description: Debug inference clients that use an attached provider and its native endpoint, including hosted APIs and host-local Ollama, vLLM, SGLang, TRT-LLM, LM Studio, or NIM. Use for provider attachment, endpoint policy, credential substitution, topology, and migration from the removed managed inference endpoint. Trigger keywords - debug inference, managed inference endpoint, local inference, ollama, lm studio, vllm, sglang, trtllm, NIM, inference failing, model server unreachable, credential_endpoint_mismatch, host.openshell.internal.
---

# Debug Inference

Diagnose inference as ordinary provider-authorized network traffic. OpenShell no
longer supplies a managed inference route, rewrites request shapes, or selects a
model. The application calls the provider's native endpoint and owns its base
URL, model, request format, and timeout.

Use installed `openshell --help` output as the authority for command syntax.
Refer to the published [provider management guide](https://docs.nvidia.com/openshell/latest/how-it-works/providers/overview)
and [provider profile guide](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles)
for current behavior.

## Diagnostic Workflow

### 1. Confirm Gateway and Sandbox Context

```bash
openshell status
openshell gateway info
openshell sandbox get <sandbox>
```

For a host-local model server, `host.openshell.internal` identifies the machine
running the gateway. It does not identify the operator's laptop when the gateway
is remote. A server listening only on `127.0.0.1` may also be unreachable from a
container; bind it to an address reachable from the gateway runtime.

### 2. Inspect the Provider and Its Profile

```bash
openshell provider get <provider>
openshell profile export <profile-id> -o yaml
```

Check that the profile:

- Names the exact endpoint host, port, and protocol the client calls.
- Allows the client binary.
- Declares the credential key and intended authentication style.
- Uses narrow HTTP rules when the provider should expose only part of an API.

For a custom or self-hosted OpenAI-compatible endpoint, import an
endpoint-bearing profile. A base URL stored only in provider configuration does
not authorize a new endpoint.

```bash
openshell profile lint -f ./provider-profile.yaml
openshell profile import -f ./provider-profile.yaml
openshell provider create --name <provider> --type <profile-id>
```

Add the required `--credential KEY` or `--credential KEY=VALUE` arguments shown
by the profile. Never broaden endpoint policy merely to silence a credential
binding error.

### 3. Confirm Attachment

```bash
openshell sandbox provider list <sandbox>
openshell sandbox provider attach <sandbox> <provider> --wait --timeout 30
```

Save the change's `receipt_id` and use `openshell sandbox provider status <sandbox> <provider> --receipt <receipt-id> --wait --timeout 30` to check when it takes effect. Success confirms that the sandbox applied the credentials, policy, and environment for new processes. If the result is pending, failed, withheld, or superseded, inspect its reason before launching the client.

Launch the client after the attachment wait succeeds so it receives the updated environment:

```bash
openshell sandbox exec <sandbox> -- <client-command>
```

After updating an ordinary static provider, wait for that change and launch a new client. An existing process keeps its revision-scoped reference; readiness does not make the old reference resolve the replacement value. Diagnose managed-refresh credentials according to their own lifecycle.

Keep credentials and issued references out of diagnostic output. Acknowledged detach revokes future credential resolution and removes the reference from future process environments. Requests already forwarded may still finish:

```bash
openshell sandbox provider detach <sandbox> <provider> --wait --timeout 30
```

### 4. Verify Native Client Configuration

The application must use the real upstream contract:

- Native provider base URL, not the retired managed virtual endpoint.
- Real model ID, not a placeholder that OpenShell used to rewrite.
- Native OpenAI, Anthropic, Vertex, or other provider request shape.
- Application-owned timeout and retry settings.
- The credential environment variable declared by the attached profile.

Probe the exact endpoint from a newly launched sandbox process. Start with a
non-secret discovery endpoint when the provider offers one, then send a minimal
inference request using the provider's documented API shape.

### 5. Interpret Common Failures

| Symptom | Likely cause | Fix |
|---|---|---|
| `credential_placeholder_in_request_body` | A body reference is invalid/revoked, or classification metadata is unavailable | Check the controlled denial reason; remove the reference from conversation history or restore provider access. Do not enable body credential rewriting or bypass flags to send tool output. Unknown literals and valid issued placeholders pass unchanged, including the model provider’s own placeholder. Header resolution does not enable body rewriting. |
| A retired managed endpoint fails DNS resolution | Client still uses the removed managed endpoint | Configure the provider's native base URL and attach an endpoint-bearing provider profile |
| Direct request is denied | Missing attachment, endpoint policy, HTTP rule, or binary authorization | Inspect the attached provider profile and sandbox effective policy |
| `credential_endpoint_mismatch` | Credential profile does not authorize the request recipient | Correct the host/port/path or import a narrowly scoped profile for the intended endpoint |
| `request_authority_mismatch` | HTTP authority differs from the CONNECT destination | Use the same host and effective port in both authorities |
| Credential variable is absent | Provider was not attached when this process launched, or profiles collide on a key | Attach the provider and launch a new process; resolve duplicate keys explicitly |
| Upstream rejects the model or body | Client relied on removed model/request rewriting | Configure the real model and provider-native request format in the application |
| `127.0.0.1` works on the host but not in the sandbox | Loopback refers to different runtime | Use `host.openshell.internal` or another gateway-reachable endpoint and profile |
| Host-local request times out | Server bind address, gateway topology, or host firewall blocks container-to-host traffic | Verify the listener and permit only the required gateway network path and port |

## Host-Local Inference Checklist

For Ollama, LM Studio, vLLM, SGLang, TRT-LLM, and local NIM deployments:

1. Verify the engine from the gateway host.
2. Verify it listens on an address reachable from the gateway runtime.
3. Import a custom profile naming `host.openshell.internal` and the actual port.
4. Restrict the profile to the intended binaries and API paths.
5. Create and attach the provider.
6. Configure the application's base URL, model, and timeout.
7. Probe the native endpoint from a newly launched sandbox process.

## Reporting

Report:

1. The active gateway and whether topology contributes to the failure.
2. The provider, profile, attachment, endpoint, and client binary involved.
3. The exact failed host, port, path, and request authority without secrets.
4. Whether the client still relies on removed managed-routing behavior.
5. The narrowest profile, attachment, or application configuration change that
   resolves the problem.
