---
name: debug-inference
description: Debug why inference.local or external inference setup is failing. Use when the user cannot reach a local model server, has provider base URL issues, sees inference verification failures, hits protocol mismatches, or needs to diagnose inference on local vs remote gateways. Trigger keywords - debug inference, inference.local, local inference, ollama, vllm, sglang, trtllm, NIM, inference failing, model server unreachable, failed to verify inference endpoint, host.openshell.internal.
---

# Debug Inference

Diagnose why OpenShell inference is failing and recommend exact fix commands.

Use `openshell` CLI commands to inspect the active gateway, provider records, managed inference config, and sandbox behavior. Use a short sandbox probe when needed to confirm end-to-end routing.

## Overview

OpenShell supports two different inference paths. Diagnose the correct one first.

1. **Managed inference** through `https://inference.local`
   - Configured by `openshell inference set`
   - Shared by every sandbox on the active gateway
   - Credentials and model are injected by OpenShell
2. **Direct external inference** to hosts like `api.openai.com`
   - Controlled by `network_policies`
   - Requires the application to call the external host directly
   - Requires provider attachment and network access to be configured separately

For local or self-hosted engines such as Ollama, vLLM, SGLang, TRT-LLM, and many NIM deployments, the most common managed inference pattern is an `openai` provider with `OPENAI_BASE_URL` pointing at a host the gateway can reach.

## Prerequisites

- `openshell` is on the PATH
- The active gateway is running
- You know the failing setup, or can infer it from commands and config

## Tools Available

Use these commands first:

```bash
# Which gateway is active, and can the CLI reach it?
openshell status

# Show managed inference config for inference.local
openshell inference get

# Inspect the provider record referenced by inference.local
openshell provider get <provider-name>

# Inspect gateway topology details when remote/local confusion is suspected
openshell gateway info

# Run a minimal end-to-end probe from a sandbox
openshell sandbox create -- curl https://inference.local/v1/chat/completions --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

## Workflow

When the user asks to debug inference, run diagnostics automatically in this order. Stop and report findings as soon as a root cause is identified.

### Determine Context

Establish these facts first:

1. Is the application calling `https://inference.local` or a direct external host?
2. Which gateway is active, and is it local, remote, or cloud?
3. Which provider and model are configured for managed inference?
4. Is the upstream local to the gateway host, or somewhere else?

### Step 0: Check the Active Gateway

Run:

```bash
openshell status
openshell gateway info
```

Look for:

- Active gateway name and endpoint
- Whether the gateway is local or remote
- Whether `host.openshell.internal` would point to the local machine or a remote host

Common mistake:

- **Laptop-local model + remote gateway**: `host.openshell.internal` points to the remote gateway host, not your laptop. A laptop-local Ollama or vLLM server will not be reachable without a tunnel or shared reachable network path.

### Step 1: Check Whether Managed Inference Is Configured

Run:

```bash
openshell inference get
```

Interpretation:

- **`Not configured`**: `inference.local` has no backend yet. Fix by configuring it:

  ```bash
  openshell inference set --provider <name> --model <id>
  ```

- **Provider and model shown**: Continue to provider inspection.

### Step 2: Inspect the Provider Record

Run:

```bash
openshell provider get <provider-name>
```

Check:

- Provider type matches the client API shape
  - `openai` for OpenAI-compatible engines such as Ollama, vLLM, SGLang, TRT-LLM, and many NIM deployments
  - `anthropic` for Anthropic Messages API
  - `nvidia` for NVIDIA-hosted OpenAI-compatible endpoints
- Required credential key exists
- `*_BASE_URL` override is correct when using a self-hosted endpoint

Fix examples:

```bash
openshell provider create --name ollama --type openai --credential OPENAI_API_KEY=empty --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1

openshell provider update ollama --type openai --credential OPENAI_API_KEY=empty --config OPENAI_BASE_URL=http://host.openshell.internal:11434/v1
```

### Step 3: Check Local Host Reachability

For host-backed local inference, confirm the upstream server:

- Binds to `0.0.0.0`, not only `127.0.0.1`
- Runs on the same machine as the gateway
- Is reachable through `host.openshell.internal`, the host's LAN IP, or another reachable hostname

Common mistakes:

- **Base URL uses `127.0.0.1` or `localhost`**: usually wrong for managed inference. Replace with `host.openshell.internal` or the host's LAN IP.
- **Server binds only to loopback**: reconfigure it to bind to `0.0.0.0`.
- **Inference engine runs as a system service**: changing the bind address may require updating the service configuration and restarting the service before the new listener becomes reachable.

### Step 4: Check Request Shape

Managed inference only works for `https://inference.local` and supported inference API paths.

Supported patterns include:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/responses`
- `POST /v1/messages`
- `GET /v1/models`

Common mistakes:

- **Wrong scheme**: `http://inference.local` instead of `https://inference.local`
- **Unsupported path**: request does not match a known inference API
- **Protocol mismatch**: Anthropic client against an `openai` provider, or vice versa

Fix guidance:

- Use a supported path and provider type
- Point OpenAI-compatible SDKs at `https://inference.local/v1`
- If the SDK requires an API key, pass any non-empty placeholder such as `test`

### Step 5: Probe from a Sandbox

Run a minimal request from inside a sandbox:

```bash
openshell sandbox create -- curl https://inference.local/v1/chat/completions --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

Interpretation:

- **`cluster inference is not configured`**: set the managed route with `openshell inference set`
- **`connection not allowed by policy`** on `inference.local`: unsupported method or path
- **`no compatible route`**: provider type and client API shape do not match
- **Connection refused / upstream unavailable / verification failures**: base URL, bind address, topology, or credentials are wrong

### Step 6: Reapply or Repair the Managed Route

After fixing the provider, repoint `inference.local`:

```bash
openshell inference set --provider <name> --model <id>
```

If the endpoint is intentionally offline and you only want to save the config:

```bash
openshell inference set --provider <name> --model <id> --no-verify
```

Inference updates are hot-reloaded to all sandboxes on the active gateway within about 5 seconds by default.

### Step 7: Diagnose Direct External Inference

If the application calls `api.openai.com`, `api.anthropic.com`, or another external host directly, this is not a managed inference issue.

Check instead:

1. The application is configured to call the external hostname directly
2. A provider with the needed credentials exists
3. The sandbox is launched with that provider attached
4. `network_policies` allow that host, port, and HTTP rules

Use the `generate-sandbox-policy` skill when the user needs help authoring policy YAML.

## Fix: Local Host Inference Timeouts (Firewall)

Use this fix when a sandbox can reach `https://inference.local`, but OpenShell reports an upstream timeout against a host-local backend such as Ollama.

Example symptom:

```json
{"error":"request to http://host.docker.internal:11434/v1/models timed out"}
```

### When This Happens

This failure commonly appears on Linux hosts that:

- Run the OpenShell gateway in Docker
- Route `inference.local` to a host-local OpenAI-compatible endpoint such as Ollama
- Have a host firewall or networking configuration that denies container-to-host traffic by default

In this case, OpenShell routing is usually working correctly. The failing hop is container-to-host traffic on the backend port.

### Why CoreDNS Is Not the Cause

This is not the same issue as the Colima CoreDNS fix.

OpenShell injects `host.docker.internal` and `host.openshell.internal` into sandbox pods with `hostAliases`. That path bypasses cluster DNS lookup. If the request still times out, the usual cause is host firewall or network policy, not CoreDNS.

### Verify the Problem

1. Confirm the model server works on the host:

   ```bash
   curl -sS http://127.0.0.1:11434/v1/models
   ```

2. Confirm the host gateway address also works on the host:

   ```bash
   curl -sS http://172.17.0.1:11434/v1/models
   ```

3. Test the same endpoint from the OpenShell cluster container:

   ```bash
   docker exec openshell-cluster-<gateway> wget -qO- -T 5 http://host.docker.internal:11434/v1/models
   ```

If steps 1 and 2 succeed but step 3 times out, the host firewall or network configuration is blocking the container-to-host path.

### Fix

Allow the Docker bridge network used by the OpenShell cluster to reach the host-local inference port. The exact command depends on your firewall tooling (iptables, nftables, firewalld, UFW, etc.), but the rule should allow:

- **Source**: the Docker bridge subnet used by the OpenShell cluster container (commonly `172.18.0.0/16`)
- **Destination**: the host gateway IP injected into sandbox pods for `host.docker.internal` (commonly `172.17.0.1`)
- **Port**: the inference server port (e.g. `11434/tcp` for Ollama)

To find the actual values on your system:

```bash
# Docker bridge subnet for the OpenShell cluster network
docker network inspect $(docker network ls --filter name=openshell -q) --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'

# Host gateway IP visible from inside the container
docker exec openshell-cluster-<gateway> cat /etc/hosts | grep host.docker.internal
```

Adjust the source subnet, destination IP, or port to match your local Docker network layout.

### Verify the Fix

1. Re-run the cluster container check:

   ```bash
   docker exec openshell-cluster-<gateway> wget -qO- -T 5 http://host.docker.internal:11434/v1/models
   ```

2. Re-test from a sandbox:

   ```bash
   curl -sS https://inference.local/v1/models
   ```

Both commands should return the upstream model list.

### If It Still Fails

- Confirm the backend listens on a host-reachable address: `ss -ltnp | rg ':11434\b'`
- Confirm the provider points at the host alias path you expect: `openshell provider get <provider-name>`
- Confirm the active inference route: `openshell inference get`
- Inspect sandbox logs for upstream timeout details: `openshell logs <sandbox-name> --since 10m`

## Common Failure Patterns

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `openshell inference get` shows `Not configured` | No managed inference route configured | `openshell inference set --provider <name> --model <id>` |
| `failed to verify inference endpoint` | Bad base URL, wrong credentials, wrong provider type, or upstream not reachable | Fix provider config, then rerun `openshell inference set`; use `--no-verify` only when the endpoint is intentionally offline |
| Base URL uses `127.0.0.1` | Loopback points at the wrong runtime | Use `host.openshell.internal` or another gateway-reachable host |
| Local engine works only when gateway is local | Gateway moved to remote host | Run the engine on the gateway host, add a tunnel, or use direct external access |
| `connection not allowed by policy` on `inference.local` | Unsupported path or method | Use a supported inference API path |
| `no compatible route` | Provider type does not match request shape | Switch provider type or change the client API |
| Direct call to external host is denied | Missing policy or provider attachment | Update `network_policies` and launch sandbox with the right provider |
| SDK fails on empty auth token | Client requires a non-empty API key even though OpenShell injects the real one | Use any placeholder token such as `test` |
| Upstream timeout from container to host-local backend | Host firewall or network config blocks container-to-host traffic | Allow the Docker bridge subnet to reach the inference port on the host gateway IP (see firewall fix section above) |

## Full Diagnostic Dump

Run this when you want a compact report before deciding on a fix:

```bash
echo "=== Gateway Status ==="
openshell status

echo "=== Gateway Info ==="
openshell gateway info

echo "=== Managed Inference ==="
openshell inference get

echo "=== Providers ==="
openshell provider list

echo "=== Selected Provider ==="
openshell provider get <provider-name>

echo "=== Sandbox Probe ==="
openshell sandbox create -- curl https://inference.local/v1/chat/completions --json '{"messages":[{"role":"user","content":"hello"}],"max_tokens":10}'
```

When you report back, state:

1. Which inference path is failing (`inference.local` vs direct external)
2. Whether gateway topology is part of the problem
3. The most likely root cause
4. The exact fix commands the user should run
