---
name: debug-inference
description: Debug native inference access through attached provider profiles. Use when a sandbox cannot reach an inference API, credentials are not injected, a local model server is unreachable, or an application has a provider base URL or protocol mismatch. Trigger keywords - debug inference, local inference, ollama, vllm, sglang, trtllm, NIM, inference failing, model server unreachable, provider endpoint, host.openshell.internal.
---

# Debug Inference

Diagnose provider-native inference from an OpenShell sandbox and recommend exact fix commands.

OpenShell does not expose a managed inference hostname or rewrite inference requests. A sandbox calls the provider's native endpoint, chooses the model, and controls request timeouts through its application or SDK. OpenShell attaches provider policy and injects credentials only for destinations declared by that provider profile.

## Collect State

Confirm the active gateway, provider, and sandbox attachment:

```bash
openshell status
openshell provider list
openshell provider get <provider-name>
openshell sandbox provider list <sandbox-name>
```

If the provider is missing from the sandbox, attach it:

```bash
openshell sandbox provider attach <sandbox-name> <provider-name>
```

Use `openshell provider profile export <profile-id> --output yaml` to inspect the profile behind the provider. Check that it declares:

- The exact upstream host and port.
- The client binary path used inside the sandbox.
- The credential environment variable expected by the client.
- The correct inference protocol and access mode.

Static credentials fail closed when the request destination falls outside the profile. A configured base URL alone does not add an endpoint to a built-in profile; import an endpoint-bearing custom profile for alternate or self-hosted endpoints.

## Diagnose Native Provider Access

Check the application configuration before probing the network:

- OpenAI-compatible clients should use the endpoint required by the provider, usually ending in `/v1`.
- Anthropic clients must use the provider's Messages API endpoint and expected environment variables.
- Vertex AI clients must construct the native regional or global Vertex endpoint and select a supported protocol.
- The application, not OpenShell, selects the model and timeout.
- The request authority must match the CONNECT tunnel host and effective port.

Run a minimal probe with the same binary, hostname, and API shape as the application. For example:

```bash
openshell sandbox connect <sandbox-name>
curl -v https://api.openai.com/v1/models
```

Interpret common failures:

| Symptom | Likely cause | Action |
|---|---|---|
| Provider is not listed for the sandbox | Provider was never attached | Run `openshell sandbox provider attach` |
| `credential_endpoint_mismatch` | Host, port, or path is outside the profile binding | Fix the base URL or import a matching custom profile |
| `request_authority_mismatch` | HTTP authority differs from the CONNECT destination | Make the URL and `Host` authority identical, including a non-default port |
| Connection denied by policy | Profile lacks the endpoint or client binary | Update and re-import the profile with the narrow required grants |
| Upstream returns 401 or 403 | Wrong credential key, value, scope, or provider protocol | Inspect the provider and client environment variable names |
| Upstream returns 404 or protocol errors | Wrong base path or API shape | Use the provider-native endpoint and matching SDK |

## Diagnose a Host-local Model Server

For Ollama, vLLM, SGLang, TRT-LLM, or a local NIM deployment:

1. Bind the model server to an address the gateway can reach, commonly `0.0.0.0`.
2. Use `host.openshell.internal`, the host LAN address, or another gateway-reachable hostname. Do not use sandbox-local `localhost`.
3. Import a custom profile whose endpoint matches that host and port and whose binaries include the inference client.
4. Create the provider from that profile, attach it to the sandbox, and configure the application's base URL.

Example provider creation after importing an `ollama-openai` profile:

```bash
openshell provider create \
  --name ollama \
  --type ollama-openai \
  --credential OPENAI_API_KEY=unused \
  --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1
openshell sandbox provider attach <sandbox-name> ollama
```

If the gateway is remote, `host.openshell.internal` refers to the gateway host, not the user's workstation. Run the model beside that gateway or use a network-reachable address explicitly allowed by the profile.

## Upgrade Note

Current OpenShell versions do not provide `openshell inference`, `inference.local`, or the platform-only `sandbox-system` route. When diagnosing a workload created before this change:

- Attach an inference provider to every sandbox that needs it.
- Change the application to call the provider's native endpoint.
- Move model and timeout selection into the application.
- Import a custom endpoint-bearing profile for private or alternate endpoints.
- Restart or recreate the sandbox so processes no longer retain the retired hostname.

Stored managed-route records are removed during gateway migration. They cannot be converted automatically because they did not identify sandbox attachments, client binaries, or the endpoint policy required for safe native access.

## References

- [Inference Providers](https://docs.nvidia.com/openshell/latest/sandboxes/inference-routing.md)
- [Manage Providers](https://docs.nvidia.com/openshell/latest/sandboxes/manage-providers.md)
- [Provider Profiles](https://docs.nvidia.com/openshell/latest/providers/profiles.md)
