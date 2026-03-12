# Sandbox Policy Quickstart

See how OpenShell's network policy system works in under five minutes.
You'll create a sandbox, watch a request get blocked by the default-deny
policy, apply a fine-grained L7 rule, and verify that reads are allowed
while writes are blocked — all without restarting anything.

## Prerequisites

- A running OpenShell gateway (`openshell gateway start`)
- Docker daemon running

## What's in this example

| File          | Description                                                          |
| ------------- | -------------------------------------------------------------------- |
| `policy.yaml` | L7 read-only policy for the GitHub REST API, scoped to `curl`        |
| `demo.sh`     | Automated script that runs the full walkthrough non-interactively    |

## Walkthrough

### 1. Create a sandbox

```bash
openshell sandbox create --name demo --keep --no-auto-providers
```

`--keep` keeps the sandbox running after you exit so you can reconnect
later. `--no-auto-providers` skips the provider setup prompt since this
demo doesn't use an AI agent.

You'll land in an interactive shell inside the sandbox:

```
sandbox@demo:~$
```

### 2. Try to reach the GitHub API — blocked

```bash
curl -s https://api.github.com/zen
```

The request fails. By default, **all outbound network traffic is denied**.
The sandbox proxy intercepted the HTTPS CONNECT request to
`api.github.com:443` and rejected it because no network policy authorizes
`curl` to reach that host.

```
curl: (56) Received HTTP code 403 from proxy after CONNECT
```

Exit the sandbox (the sandbox stays alive thanks to `--keep`):

```bash
exit
```

### 3. Check the deny log

```bash
openshell logs demo --since 5m
```

You'll see a line like:

```
action=deny dst_host=api.github.com dst_port=443 binary=/usr/bin/curl deny_reason="no matching network policy"
```

Every denied connection is logged with the destination, the binary that
attempted it, and the reason. Nothing gets out silently.

### 4. Apply the read-only GitHub API policy

Review the policy:

```bash
cat examples/sandbox-policy-quickstart/policy.yaml
```

```yaml
version: 1

# Default sandbox filesystem and process settings.
# These static fields are required when using `openshell policy set`
# because it replaces the entire policy.
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  github_api:
    name: github-api-readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
```

The top section preserves the default sandbox filesystem and process
settings (required because `policy set` replaces the entire policy).
The `network_policies` section is the interesting part: **curl may make
GET, HEAD, and OPTIONS requests to `api.github.com` over HTTPS.
Everything else is denied.** The proxy terminates TLS (`tls: terminate`)
to inspect each HTTP request and enforce the `read-only` access preset
at the method level.

Apply it:

```bash
openshell policy set demo \
  --policy examples/sandbox-policy-quickstart/policy.yaml \
  --wait
```

`--wait` blocks until the sandbox confirms the new policy is loaded.
No restart required — policies are hot-reloaded.

### 5. Connect and verify: GET works

```bash
openshell sandbox connect demo
```

```bash
curl -s https://api.github.com/zen
```

```
Anything added dilutes everything else.
```

It works. Try a more visual endpoint:

```bash
curl -s https://api.github.com/octocat
```

```
               MMM.           .MMM
               MMMMMMMMMMMMMMMMMMM
               MMMMMMMMMMMMMMMMMMM      ____________________________
              MMMMMMMMMMMMMMMMMMMMM    |                            |
             MMMMMMMMMMMMMMMMMMMMMMM   | Speak like a human.       |
            MMMMMMMMMMMMMMMMMMMMMMMM   |_   ________________________|
            MMMM::- -:::::::- -::MMMM    |/
             MM~:~ 00~:::::~ 00~:~MM
        .. MMMMM::.00:::+:::.00teleMMM ..
              .MM::::: ._. :::::MM.
                 MMMM;:::::;MMMM
          -MM        MMMMMMM
          ^  M+     MMMMMMMMM
              MMMMMMM MM MM MM
                   MM MM MM MM
                   MM MM MM MM
                .~~MM~MM~MM~MM~~.
             ~~~~MM:~MM~~~MM~:MM~~~~
            ~~~~~~==googler======~~~~~~
             ~~~~~~==googler======
                 :MMMMMMMMMMM:
                 '=googler=='
```

### 6. Try a write — blocked by L7

```bash
curl -s -X POST https://api.github.com/repos/octocat/hello-world/issues \
  -H "Content-Type: application/json" \
  -d '{"title":"oops"}'
```

```json
{"error":"policy_denied","policy":"github-api-readonly","detail":"POST /repos/octocat/hello-world/issues not permitted by policy"}
```

The CONNECT request succeeded (api.github.com is allowed), but the L7
proxy inspected the HTTP method and returned **403**. `POST` is not in
the `read-only` preset. Your agent can read code from GitHub but cannot
create issues, push commits, or modify anything.

Exit the sandbox:

```bash
exit
```

### 7. Check the L7 deny log

```bash
openshell logs demo --level warn --since 5m
```

```
l7_decision=deny dst_host=api.github.com l7_action=POST l7_target=/repos/octocat/hello-world/issues l7_deny_reason="POST /repos/octocat/hello-world/issues not permitted by policy"
```

The log captures the exact HTTP method, path, and deny reason. In
production, pipe these logs to your SIEM for a complete audit trail of
every request your agent makes.

### 8. Clean up

```bash
openshell sandbox delete demo
```

## What you just saw

| State              | What happens                                    |
| ------------------ | ----------------------------------------------- |
| **Default deny**   | All outbound traffic blocked — nothing gets out  |
| **L7 read-only**   | GET to `api.github.com` allowed, POST blocked    |
| **Audit trail**    | Every request logged with method, path, decision |

The policy hot-reloads in seconds and gives
you verifiable, fine-grained control over what your agent can access —
without `--dangerously-skip-permissions`.

## Next steps

- **Customize the policy**: Change `access: read-only` to `read-write`
  or add explicit `rules` for specific paths. See the
  [security policy reference](../../architecture/security-policy.md).
- **Scope to an agent**: Replace the `binaries` section with your
  agent's binary (e.g., `/usr/local/bin/claude`) instead of `curl`.
- **Add more endpoints**: Stack multiple policies in the same file
  to allow PyPI, npm, or your internal APIs.
- **Try audit mode**: Set `enforcement: audit` to log violations
  without blocking, useful for building a policy iteratively.
