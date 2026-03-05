<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Common issues organized by area, with symptoms, causes, and fixes.

## Cluster Issues

### Docker not running

**Symptom:** CLI commands fail with a Docker connection error.

**Fix:** Start Docker Desktop or Docker Engine, then retry.

```console
$ docker info
```

If this command fails, Docker is not running.

### Port conflicts

**Symptom:** Cluster deployment fails with "port already in use" or "address already in use."

**Fix:** Another process is using a port the cluster needs. Stop the conflicting process or change the port. Check which process holds the port:

```console
$ lsof -i :<port>
```

### Cluster won't start

**Symptom:** `nemoclaw cluster status` shows the cluster is unhealthy or not running. Commands fail with connection errors.

**Fix:** Destroy the cluster and redeploy. This removes all state (sandboxes, providers, policies), so export anything you need first.

```console
$ nemoclaw cluster admin destroy
$ nemoclaw cluster admin deploy
```

## Sandbox Issues

### Sandbox stuck in Provisioning

**Symptom:** `nemoclaw sandbox get <name>` shows phase `Provisioning` and does not transition to `Ready`.

**Causes:**
- The cluster is unhealthy or overloaded.
- The container image is being pulled for the first time (large images take time).
- A resource constraint on the host.

**Fix:** Check cluster health first:

```console
$ nemoclaw cluster status
```

Then inspect the sandbox logs for errors:

```console
$ nemoclaw sandbox logs <name>
```

If the cluster itself is unhealthy, see the cluster issues section above.

### Connection refused

**Symptom:** `nemoclaw sandbox connect <name>` fails with "connection refused."

**Cause:** The sandbox is not in the `Ready` phase yet. The SSH server starts only after the supervisor finishes setting up isolation.

**Fix:** Check the sandbox phase:

```console
$ nemoclaw sandbox get <name>
```

Wait until the phase transitions to `Ready`, then retry the connection. If the sandbox is stuck in `Provisioning`, see the section above.

## Provider Issues

### "no existing local credentials/config found"

**Symptom:** `nemoclaw provider create --from-existing` fails with this error.

**Cause:** The expected environment variable is not set in your current shell session. The CLI only reads from environment variables, not config files or keychains.

**Fix:** Check whether the variable is set:

```console
$ echo $ANTHROPIC_API_KEY
```

If empty, export it and retry:

```console
$ export ANTHROPIC_API_KEY=sk-ant-...
$ nemoclaw provider create --name my-claude --type claude --from-existing
```

See {doc}`../sandboxes/providers` for the full list of variables each provider type expects.

### Provider not found

**Symptom:** `nemoclaw sandbox create --provider <name>` fails because the provider does not exist.

**Fix:** Create the provider before referencing it in sandbox creation:

```console
$ nemoclaw provider create --name my-claude --type claude --from-existing
$ nemoclaw sandbox create --provider my-claude -- claude
```

List existing providers with:

```console
$ nemoclaw provider list
```

## Policy Issues

### "failed to parse sandbox policy YAML"

**Symptom:** `nemoclaw sandbox policy set` fails with a YAML parse error.

**Cause:** The policy file contains metadata headers. This commonly happens when you export a policy with `--full` and try to reapply it directly. The `--full` output includes status metadata that is not valid in a policy input file.

**Fix:** Strip the metadata from the exported YAML. Use only the policy content (starting from `version: 1`) without any status or metadata fields added by `--full`.

### Policy shows status "failed"

**Symptom:** `nemoclaw sandbox policy list <name>` shows a policy version with status `failed`.

**Cause:** The policy YAML is syntactically valid but contains a semantic error (invalid field value, conflicting rules, etc.).

**Fix:** Check the error message in the `policy list` output. The previous policy remains active when a new policy fails to apply. Fix the error in your YAML and reapply:

```console
$ nemoclaw sandbox policy list <name>
$ nemoclaw sandbox policy set <name> --policy fixed-policy.yaml
```

## Network Issues

### Agent API calls being denied

**Symptom:** The agent cannot reach its API endpoint. Logs show `action=deny` for requests that should be allowed.

**Fix:** Check the sandbox logs for denied connections:

```console
$ nemoclaw sandbox logs <name>
```

Look for entries with `action=deny`. Verify that:

1. The endpoint (host and port) is listed in your policy's `network_policies`.
2. The calling binary's path is listed in the `binaries` for that policy entry.

Both the endpoint and binary must match for the connection to be allowed.

### Agent calls intercepted instead of going direct

**Symptom:** The agent's own API calls are being intercepted by the privacy router instead of flowing directly to the API. The agent may receive responses from a different model or fail with authentication errors.

**Cause:** The binary path in your policy does not match the actual process executable making the connection. The proxy resolves the calling binary via `/proc/<pid>/exe`. If the resolved path does not match any binary in your `network_policies` entry, the connection falls through to inference interception.

**Fix:** Check the sandbox logs for the binary path the proxy resolved:

```console
$ nemoclaw sandbox logs <name>
```

Look for the `binary_path` field in intercepted connection entries. Update your policy's `binaries` list to include the actual executable path. Common mismatches:

| Expected | Actual | Why |
|---|---|---|
| `/usr/local/bin/claude` | `/usr/bin/node` | Claude Code runs as a Node.js process. Include both paths. |
| `/usr/bin/python3` | `/usr/bin/python3.12` | Versioned Python binary. Use the exact path from the logs. |
| `/usr/local/bin/opencode` | `/usr/bin/node` | opencode runs via Node.js. Include the Node binary path. |

### Inference routing not working

**Symptom:** Userland code makes an inference API call but gets a 403 or the call is denied. The privacy router does not intercept the request.

**Causes:**
- The `allowed_routes` in the sandbox policy does not include the route's `routing_hint`.
- No inference route exists with a matching `routing_hint`.
- The inference route is disabled.

**Fix:** Check that routes exist and match:

```console
$ nemoclaw inference list
```

Verify that the route's `routing_hint` appears in your sandbox policy's `inference.allowed_routes`. Check the logs for `route_count` to confirm the router loaded the expected number of routes:

```console
$ nemoclaw sandbox logs <name>
```

## NemoClaw Terminal Issues

### Terminal shows no logs

**Symptom:** `nemoclaw gator` launches but displays no log entries.

**Cause:** No sandbox is running, or the sandbox has not started producing log output yet.

**Fix:** Check whether a sandbox is running and in the `Ready` phase:

```console
$ nemoclaw sandbox get <name>
```

If the sandbox is in `Provisioning`, wait for it to reach `Ready`. If no sandboxes exist, create one first. The NemoClaw Terminal displays logs from all active sandboxes in the cluster.
