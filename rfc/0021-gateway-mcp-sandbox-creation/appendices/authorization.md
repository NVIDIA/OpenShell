# Appendix: Authorization and Audit Details

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

The RFC's [Authorization and audit](../README.md#authorization-and-audit)
section gives the rules; this page gives the details.

## How `/mcp` reaches the router

Plain HTTP routes on the gateway are not authenticated today; only the gRPC
service is. The `/mcp` handler runs the gateway's existing authenticator
chain. A sandbox session token yields a sandbox caller. An OIDC bearer token or
a user's mTLS client certificate, which is what `openshell mcp serve` sends,
yields a user. An operator certificate is refused with "MCP is available to
users and sandboxes only", and anonymous callers are refused. On a gateway
that allows unauthenticated users for development, an anonymous caller is the
development user, and roots it creates skip the creator check.

The handler then dispatches the RPC to the gRPC router inside the gateway
process, with that caller and an in-memory marker saying the request came from
`/mcp`. The marker is a typed value in the request's extensions, not a header,
so nothing that arrives over the network can carry it. The caller's
authentication context is preserved, so interceptors see the real caller.

The parent, workspace and child-only checks run in the handlers, on the
request as it arrives after interceptors have run, so an interceptor that
rewrites a request cannot move a child to another parent or workspace.

## Sandbox callers, per method

- `CreateSandbox`: the caller must be a root. The gateway sets the parent to
  the caller and creates the child in the caller's workspace. The request may
  carry only a name, a workload template and a list of providers. A named
  template must be in the caller's workspace, carry the
  `openshell.ai/agent-usable: "true"` label and have no driver configuration;
  without one, the gateway fills in the image, CPU and memory from the caller.
  Either way the child keeps the caller's runtime class and user namespaces.
  Named providers must be attached to the caller; without any, the gateway
  fills in all of the caller's. Any other fields in the request are refused.
  A name already used by a sandbox that is not the caller's child is refused
  with `already_exists`. Names share one namespace per workspace, so a create
  can tell a sandbox that a name is taken, but nothing else about that
  sandbox.
- `ListSandboxes`: returns only the caller's children.
- `ListSandboxTemplates`: returns at most 50 templates, only those in the
  caller's workspace with the `openshell.ai/agent-usable: "true"` label and no
  driver configuration, without their environment values, whatever scope or
  selector the request names. `/mcp` calls it to build a sandbox's tool list.
- `ExecSandbox`, `DeleteSandbox`, `GetSandboxLogs`: the target's parent must be
  the caller. Any other name, including the caller's own, a sibling and a
  sandbox that does not exist, reads as "not found", so these calls cannot
  probe names.

## The recorded creator

When a user creates a sandbox, the gateway records that user in its read-only
`created_by` field. When a root creates a child through MCP, the child records
the root instead, as `sandbox:<id>`, the same form the audit log uses:
`created_by` names whoever decided to create the sandbox, and the user a root
acts for is the root's own `created_by`.

The check that this user still has access fails closed. A root created before
`created_by` existed, or by an identity that has no workspace membership to
recheck, such as an operator's client certificate, cannot create children
through MCP; the error says so. The check knows only the creator's subject,
not their roles, so a root created by a platform administrator who is not a
member of the workspace cannot create children through MCP either. Users can
still create children under such a root from the CLI or through MCP, where the
user is the caller and is checked directly.

## Audit events

Every MCP tool call is logged as one OCSF API Activity event. A call to an
unknown tool, or one whose caller fails authentication partway, is refused
without an event.

- **Actor:** the calling sandbox or user and, for a sandbox, the user it acts
  for (`acting_for`, the root's `created_by`). For a child calling `/mcp`, that
  is whoever created the child: its root, `sandbox:<id>`, when an agent
  created it, or the user when a user did.
- **Outcome:** a refusal by policy or by the request, such as not found or a
  limit, is denied with its code. An internal, unavailable or timed-out call
  is allowed but failed. For an internal, unknown or unavailable gateway
  error the agent sees only a request id; the error's text goes to the gateway
  log and the event (`error_detail`) under the same id. Other refusals keep
  their message, which is written for agents; a conflict that is worth
  retrying is reported as `unavailable` with its message. A job step that
  fails in the child returns up to 200 characters of the child's own error
  output, which is the child's data rather than the gateway's.
- **Arguments:** the target; for `create_sandbox` the template, parent, image,
  providers and new id; for `list` the filter and count; for `exec` the
  argument list, working directory, timeout and exit code; for jobs the job
  id, state and exit code. The argument list is kept because "what did it run"
  is what operators ask, and secrets belong in providers, not command lines.
- **Limits:** every field is capped (argument list 1 KiB, working directory
  512 bytes, others 256 bytes) with a cut marker, so an event stays under
  4 KiB. Stdin, environment values, output, log lines and reply bodies are
  never recorded.

Refusals at the supervisor door are logged as HTTP denials, like other egress
denials. The door refuses any `Origin` other than `openshell.local`, and
forwards only the `content-type`, `accept` and `mcp-protocol-version` headers.
