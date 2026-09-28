# Sandbox Policy Quickstart

See how OpenShell's network policy system works in under five minutes.
You'll create a sandbox, watch a request get blocked by the default-deny
policy, apply a fine-grained L7 rule, and verify that reads are allowed
while writes are blocked — all without restarting anything.

## Prerequisites

- A running OpenShell gateway (`mise run gateway:docker` for local development)
- Docker daemon running

## What's in this example

| File          | Description                                                          |
| ------------- | -------------------------------------------------------------------- |
| `policy.yaml` | Complete policy with the same rule, for `sandbox create --policy`    |
| `demo.sh`     | Automated script that runs the full walkthrough non-interactively    |

## Walkthrough

### 1. Create a sandbox

```bash
openshell sandbox create --name demo --no-auto-providers
```

`--no-auto-providers` skips the provider setup prompt since this
demo doesn't use an AI agent.

You'll land in an interactive shell inside the sandbox:

```text
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

```text
curl: (56) Received HTTP code 403 from proxy after CONNECT
```

Exit the sandbox (sandboxes are kept running by default; pass `--no-keep` at creation time to delete on exit):

```bash
exit
```

### 3. Check the deny log

```bash
openshell logs demo --since 5m --source sandbox
```

You'll see a line like:

```text
[1775014132.690] [sandbox] [OCSF ] [ocsf] NET:OPEN [MED] DENIED /usr/bin/curl(64) -> api.github.com:443 [policy:- engine:opa] [reason:network connections not allowed by policy]
```

Every denied connection is logged with the destination, the binary that
attempted it, and the reason. Nothing gets out silently.

### 4. Add a read-only GitHub API rule

```bash
openshell policy update demo \
  --rule-name github_api \
  --binary /usr/bin/curl \
  --add-endpoint api.github.com:443:read-only:rest:enforce \
  --wait
```

The endpoint specification lists the host, port, access preset, protocol,
and enforcement mode. **curl may make GET, HEAD, and OPTIONS requests to
`api.github.com` over HTTPS. Everything else is denied.** `rest` tells the
proxy to terminate TLS and inspect each HTTP request, `read-only` permits
`GET`, `HEAD`, and `OPTIONS`, and `enforce` blocks every other request.
`policy update` changes only the network rules and keeps the rest of the
sandbox's policy.

The command adds a rule equivalent to this YAML in the policy's
`network_policies` section:

```yaml
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/curl
```

`--wait` blocks until the sandbox reports a result for the new policy
revision. No restart required — network rules reload while the sandbox runs.

[`policy.yaml`](policy.yaml) contains the same rule in a complete policy. Use
it to start a new sandbox with the rule in place:
`openshell sandbox create --name demo --policy examples/sandbox-policy-quickstart/policy.yaml`.
Do not apply it to a running sandbox with `openshell policy set`, which
replaces the entire policy and is rejected if the file drops a filesystem path
the sandbox already has.

### 5. Connect and verify: GET works

```bash
openshell sandbox connect demo
```

```bash
curl -s https://api.github.com/zen
```

```text
Anything added dilutes everything else.
```

It works. Try a more visual endpoint:

```bash
curl -s https://api.github.com/octocat
```

```text
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

The proxy returns a `403` response with a JSON body that includes fields
like these:

```text
{...,"error":"policy_denied",...,"policy":"github_api",...,"rule":"POST /repos/octocat/hello-world/issues",...}
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
openshell logs demo --since 5m --source sandbox
```

```text
[1775014140.412] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST http://api.github.com:443/repos/octocat/hello-world/issues [policy:github_api engine:l7] [reason:L7_REQUEST deny POST api.github.com:443/repos/octocat/hello-world/issues reason=POST /repos/octocat/hello-world/issues not permitted by policy]
```

The log captures the exact HTTP method, path, and matching rule. Policy
events are INFO-level log records regardless of their severity, so do not
filter them out with `--level warn`. In production, export these events to
your SIEM for a complete audit trail of every request your agent makes.

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
