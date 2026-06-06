---
authors:
  - "@zanetworker"
state: draft
links:
  - "RFC 0005 / PR #1617 (shared SDK core and TS binding, @maxdubrinsky)"
  - "PR #1621 (Python SDK OIDC auth, @mrunalp)"
  - "PR #1404 (per-sandbox auth, merged)"
  - "PR #1547 (Python SDK fixes, open)"
  - "PR #1117 (Python wheels, open)"
  - "PR #1511 (proxy egress RFC, open)"
  - "Issue #1044 (SDK roadmap)"
---

# RFC 0006 - SDK Consumption Entrypoints and File Transfer

## Summary

Ship official Python and TypeScript SDKs that make OpenShell
consumable as programmable infrastructure for agent platforms and
frameworks. Add streaming UploadFile/DownloadFile gRPC RPCs to the
gateway so SDK consumers can move files in and out of sandboxes
without shelling out to the CLI. Support OIDC authentication in both
SDKs so any OIDC-enabled gateway is reachable without distributing
client certificates.

### Relationship to RFC 0005

RFC 0005 (PR #1617, @maxdubrinsky) proposes the shared Rust SDK core
and TypeScript binding via napi-rs, with a working prototype. This RFC
is complementary: it covers the broader SDK strategy (consumption
patterns, file transfer RPCs, Python SDK surface expansion, platform
integration examples) that RFC 0005 is the first implementation phase
of. RFC 0005 delivers the "how" for the shared core and TS binding;
this RFC frames the "why" and "what" across both languages.

Areas this RFC covers that RFC 0005 explicitly defers:

- File transfer RPCs (UploadFile/DownloadFile)
- Python SDK surface expansion (provider, watch, policy, services)
- Platform consumption patterns (Anthropic, OpenAI, OpenClaw, CI/CD)
- Python-on-shared-core migration path

## Motivation

Agent platforms are converging on a pattern: separate the agent's
brain (reasoning, orchestration) from its hands (code execution, tool
calls). Anthropic Managed Agents, OpenAI's Responses API and Agents
SDK, Cloudflare Sandbox, and OpenClaw all need a secure execution
layer where agent-generated code runs in isolation, credentials never
touch the execution environment, and network egress is
policy-enforced.

OpenShell is that execution layer. The gateway enforces
hardware-backed isolation (Landlock, seccomp, user namespaces), L4/L7
network policy with process identity, credential injection via proxy,
and OCSF audit logging. The gRPC API exposes 54 RPCs.

**The problem is that none of this is consumable programmatically.**

The only production client is the Rust CLI. The Python SDK wraps 8 of
54 RPCs and only supports mTLS authentication. No official TypeScript
SDK exists. No file transfer RPC exists. Every platform integration
must either shell out to the CLI binary or build a custom gRPC client
from scratch.

### Why programmatic consumption matters

Platforms and frameworks don't type commands; they make API calls. An
Anthropic worker polling a queue needs to create a sandbox, run a tool
call, and post results back, hundreds of times per hour, with no human
in the loop. An OpenAI Agents SDK adapter needs to implement
`session.write()` and `session.exec()` behind a SandboxClient
interface. A CI pipeline needs to spin up a sandbox, seed files, run
tests, and tear down, all from a script.

None of these can shell out to a CLI binary. They need a typed client
library that handles connection, auth, streaming, and error handling.

### What is blocked today

| Consumer | What they want | What blocks them |
|----------|---------------|-----------------|
| Anthropic worker | Create sandboxes, download skills, run tool calls, retrieve artifacts | No OIDC auth, no file transfer RPC |
| OpenAI Agents SDK adapter | Implement SandboxClient: materialize Manifest, exec, snapshot | No file transfer RPC (session.write() for LocalDir has no clean implementation) |
| OpenClaw plugin | Create sandboxes, sync workspace, exec commands | No TypeScript SDK (plugins are TS-only), currently shells out to CLI 5+ times per command |
| Multi-tenant platform | Per-tenant sandboxes with policies and credentials | No OIDC auth, no provider attach/detach in SDK |
| CI/CD pipeline | Sandboxed test runs with repo seeding and artifact retrieval | No file transfer RPC |

### Two sandbox patterns

OpenShell supports two usage patterns (see also the
[LangChain framing](https://www.langchain.com/blog/the-two-patterns-by-which-agents-connect-sandboxes)):

![Sandbox Patterns](sdk-modes.png)

**Agent in a Sandbox.** The agent process runs inside the sandbox.
Everything (agent logic, tool calls, code execution) is contained
within a single sandbox boundary. The agent holds no credentials and
reaches no external services except through a policy-enforced proxy.

- Interface: CLI (`openshell sandbox create --from openclaw`)
- SDK relevance: None for end users. The CLI is the interface.

**Sandbox as a Tool.** The agent runs outside the sandbox and uses it
as a disposable execution environment. The agent (or the platform
orchestrating it) creates sandboxes, sends code to run, and reads
results back. Credentials are separated from the execution
environment.

- Interface: SDK (Python or TypeScript)
- SDK relevance: Primary use case. This is what the RFC enables.

The same OpenShell SDKs and APIs are used regardless of who invokes
them. The invoker may be a platform worker (Anthropic Managed Agents,
OpenAI Responses API local shell), an agent framework (OpenAI Agents
SDK, OpenClaw, LangChain), or a custom script (CI/CD pipeline). From
OpenShell's perspective, these are all "Sandbox as a Tool" consumers
using the same SDK surface.

Where the invocation originates determines where to contribute if
OpenShell compatibility needs a change:

| Consumption entrypoint | Who invokes OpenShell | Where to contribute |
|------------------------|----------------------|---------------------|
| Platform API (e.g. Responses API, Managed Agents) | Platform worker on your infra | Implement the platform's sandbox contract (e.g. containers API) using OpenShell SDK |
| Agent framework (e.g. OpenAI Agents SDK, OpenClaw) | Framework's sandbox extension | Implement the framework's SandboxClient interface using OpenShell SDK |
| Direct SDK usage (e.g. CI/CD, custom scripts) | Your code | Call OpenShell SDK directly |

## Non-goals

- **SSH session management in the SDK.** CLI convenience for humans.
  SDKs use ExecSandbox.
- **Supervisor protocol exposure.** ConnectSupervisor/RelayStream are
  internal. SDK consumers never talk to the supervisor directly.
- **Draft policy workflow in the SDK.** Operator approval UI concern,
  not a programmatic SDK concern.
- **Replacing the CLI.** The CLI remains the interface for "Agent in
  a Sandbox" and for platform engineers. The SDK serves programmatic
  "Sandbox as a Tool" consumers.
- **Per-principal sandbox isolation.** OIDC gives authentication
  (who is calling) but does not by itself give tenant isolation. The
  gateway does not currently filter sandbox visibility per principal.
  This RFC adds OIDC support to the SDK for identity and
  cross-deployment connectivity, not for multi-tenancy enforcement.
  Per-principal sandbox scoping is a gateway-side feature that should
  be addressed separately.

## Proposal

### 1. Extend the Python SDK

Add wrappers for existing gateway RPCs. No gateway changes needed.

| Method | RPC | Why |
|--------|-----|-----|
| OIDC auth | gRPC metadata interceptor | mTLS-only requires distributing client certificates to every SDK consumer. OIDC bearer tokens let any consumer connect to an OIDC-enabled gateway without certificate distribution, regardless of deployment model. |
| `attach_provider()` / `detach_provider()` / `list_providers()` | AttachSandboxProvider, DetachSandboxProvider, ListSandboxProviders | Credential separation is core to "Sandbox as a Tool." Without it, SDK consumers must bake credentials into sandbox images or pass them as env vars visible to agent code. |
| `create_provider()` / `get_provider()` / `update_provider()` / `delete_provider()` | CreateProvider, GetProvider, UpdateProvider, DeleteProvider | API parity with the CLI. Platforms onboarding tenants programmatically need full provider lifecycle without a human running CLI commands. |
| `watch()` | WatchSandbox | Polling at scale is untenable. Platforms need real-time status, logs, and error detection. |
| `upload_path()` / `download_path()` | UploadFile, DownloadFile (new RPCs, see below) | Every use case involving local files is blocked without this. |

Should-have (wrapping existing RPCs):

| Method | RPC | Why |
|--------|-----|-----|
| `update_policy()` / `get_policy()` | UpdateConfig, GetSandboxConfig | Multi-tenant per-sandbox policies |
| `expose_service()` / service CRUD | ExposeService, GetService, ListServices, DeleteService | Sandbox-hosted HTTP services |
| `get_logs()` | GetSandboxLogs | One-shot log retrieval for debugging |

### 2. Streaming file transfer (dependency, design deferred)

The SDK needs `upload_path()` and `download_path()` methods, but
these require new UploadFile/DownloadFile gRPC RPCs in the gateway
that do not exist today. The detailed proto contract and routing
design are tracked separately in
[#1707](https://github.com/NVIDIA/OpenShell/issues/1707).

**Why file transfer is needed:**

The OpenAI Agents SDK illustrates this concretely. A developer writes:

```python
manifest = Manifest(entries={"repo": LocalDir(src="./myproject")})
```

This means "copy my local directory into the sandbox." The SDK calls
`session.write()` per file during materialization. Without an
UploadFile RPC, `session.write()` has no clean implementation. The
adapter either raises NotImplementedError or falls back to piping
each file through `exec(["cat", ">", path], stdin=bytes)`, which
breaks on binary content, has size limits, and loses permissions.

Every platform integration has the same pattern:

| Platform | Upload needed for | Download needed for |
|----------|------------------|---------------------|
| Anthropic | Skills to `/workspace/skills/` | Agent output artifacts |
| OpenAI Agents SDK | Manifest LocalDir entries | Sandbox outputs |
| OpenClaw (mirror mode) | Workspace before every command | Changes after every command |
| CI/CD | Repo checkout, test fixtures | Coverage reports, build artifacts |

This RFC identifies the need. The design of streaming file transfer
is deferred to #1707.

### 3. Ship a TypeScript SDK

New package at `typescript/openshell/` (or standalone repo, see Open
Questions). Same surface as the Python SDK. Generated from the same
proto files using `buf`. Published to npm. Built with OIDC auth from
day one.

Primary consumer: OpenClaw. The current plugin shells out to the CLI
binary 5+ times per command cycle. The TypeScript SDK replaces those
subprocess calls with direct gRPC calls.

### 4. OIDC authentication in both SDKs

The gateway already validates JWTs (PR #935 merged). The CLI already
supports OIDC auth flows (PR #1535 merged). The SDK just needs to
send the token.

Implementation: a gRPC call credentials interceptor that attaches
`authorization: Bearer <token>` as metadata on every call. Roughly
20 lines per SDK.

```python
# mTLS (today): client certificates distributed to every consumer
client = SandboxClient(endpoint=..., tls=TlsConfig(ca_path=..., cert_path=..., key_path=...))

# OIDC (proposed): one token from your existing IdP
client = SandboxClient(endpoint=..., auth=OidcAuth(token=os.environ["OIDC_TOKEN"]))
```

**Why this is required, not nice-to-have:** mTLS requires distributing
client certificates to every SDK consumer. Each consumer needs the CA
cert, client cert, and client key, and must re-distribute on every
rotation. In multi-tenant or multi-host deployments, that's N
consumers each needing a copy. OIDC eliminates this: the SDK sends a
JWT, the gateway validates against the IdP's public keys, no
certificates to distribute.

## Implementation plan

### Phase dependencies

![Phase Dependencies](sdk-phase-deps.png)

Phase 1 and Phase 2 run in parallel. Phase 3 waits for both. Phase 4
proves everything works. Phase 5 is independent.

### Phase 1: Foundation (SDK-only, no gateway changes)

- OIDC gRPC interceptor in Python SDK
- `attach_provider()` / `detach_provider()` / `list_providers()`
- `watch()` wrapping WatchSandbox
- Tests

**Enables:** Remote-mode workloads (git clone inside sandbox, no file
transfer needed). OIDC auth for any gateway deployment. Credential
separation via provider attach.

**Related PRs:** #1404 (auth foundation, merged), #1547 (Python SDK
work, open), #1117 (Python wheels, open).

### Phase 2: File Transfer (design tracked in #1707)

- Design and implement streaming file transfer RPCs (see
  [#1707](https://github.com/NVIDIA/OpenShell/issues/1707))
- `upload_path()` / `download_path()` in Python SDK
- Unit + integration tests

![Anthropic Worker Flow](sdk-anthropic-worker.png)

**Enables:** All file-dependent use cases. Anthropic skill downloads,
OpenAI Manifest materialization, OpenClaw mirror mode, CI/CD repo
seeding.

### Phase 3: TypeScript SDK

- Set up package with buf proto generation
- Core client (CRUD, exec, wait, health) with OIDC from day one
- Provider attach/detach, watch, file transfer
- Publish to npm
- Tests

**Enables:** OpenClaw plugin rewrite. Node.js framework integrations.

### Phase 4: Integration examples

- Anthropic self-hosted worker using Python SDK (platform entrypoint)
- OpenAI Agents SDK sandbox provider using Python SDK (framework entrypoint)
- OpenClaw plugin rewrite using TypeScript SDK (framework entrypoint)

**Enables:** Proof that it works end-to-end. Reference implementations
for other integrations.

### Phase 5: Policy + Services (independent, SDK-only)

- `update_policy()` / `get_policy()` in both SDKs
- `expose_service()` / service CRUD in both SDKs
- `get_logs()` in both SDKs

**Enables:** Multi-tenant per-sandbox policies. Sandbox-hosted HTTP
services. Log retrieval.

## Alternatives

### Do nothing

SDK consumers continue shelling out to the CLI binary. This works but
creates packaging dependencies (init containers, curl downloads),
performance overhead (5+ subprocess calls per command cycle), and
prevents clean integration with platform SDKs (Anthropic, OpenAI)
that expect typed client interfaces.

### Tar-over-exec-stdin for file transfer

Instead of new RPCs, use `exec(["tar", "xz", "-C", "/path"],
stdin=tarball)` for uploads and `exec(["tar", "cz", "/path"])` for
downloads. This works for small files but breaks on large transfers
(4MB default gRPC message size), provides no progress reporting, has
no resume on failure, loses permissions inconsistently, and requires
`tar` in the sandbox image. This alternative and others will be
evaluated in the file transfer design (#1707).

### Adopt community TypeScript SDK

Fork or bless `moonshot-partners/openshell-node` instead of building
in-repo. This avoids the new-package cost but introduces a dependency
on a single external maintainer with no release alignment to
OpenShell releases. Proto sync becomes manual.

## Open questions

1. **File transfer archive format.** The proto uses `is_archive` with
   tar. Should this be tar, tar.gz, tar.zstd, or configurable?
   Recommendation: tar (uncompressed). gRPC already compresses at the
   transport layer when enabled.

2. **OIDC audience naming.** The gateway default is
   `server.oidc.audience = "openshell-cli"`. Now that the SDK is a
   first-class client, should this be renamed to `openshell-api` or
   `openshell-gateway`?

3. **npm package name.** `@openshell/sdk`, `openshell`, or
   `openshell-sdk`? Should align with the Python package name
   (`openshell` on PyPI).

4. **Relationship to #1617 (shared Rust core).** This RFC defines
   what the SDK exposes. #1617 defines how it is implemented (shared
   Rust core with thin language bindings). The two RFCs should close
