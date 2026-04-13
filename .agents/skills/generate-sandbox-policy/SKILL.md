---
name: generate-sandbox-policy
description: Generate sandbox security policies from plain-language requirements and optional REST API documentation. At minimum, takes API host:port endpoints and intent to produce preset-based or L4 policies. With full API docs (OpenAPI, Swagger, markdown), generates fine-grained per-endpoint L7 rules. Trigger keywords - generate policy, create policy, update policy, change policy, sandbox policy, network policy, API policy, security policy, allow API, restrict API.
---

# Generate Sandbox Policy

Generate YAML sandbox network policies from REST API documentation and natural-language user requirements.

## Overview

This skill translates a user's plain-language policy intent into a valid sandbox policy. The amount of detail the user provides determines the granularity of the generated policy — from broad L4 or preset-based policies (just a host:port) up to fine-grained per-endpoint L7 rules (full API docs).

The output is a `network_policies` YAML block (and optionally a full policy file) that conforms to the sandbox policy schema.

## Step 1: Gather Inputs

### Determine the Detail Tier

The user's input falls into one of three tiers. Work with whatever the user provides — **do not require a higher tier than needed**.

| Tier | User provides | What you can generate |
|------|--------------|----------------------|
| **Minimal** | Host(s) and plain-language intent | L4-only policies, or L7 with access presets (`read-only`, `read-write`, `full`) |
| **Moderate** | Host(s) + some known URL paths or resources | L7 with targeted glob rules for known paths, presets for the rest |
| **Full** | Complete API docs (OpenAPI, Swagger, markdown, URL) | Fine-grained per-endpoint L7 rules with specific method+path combinations |

### Minimal Tier (host + intent only)

The user provides API endpoints and a broad intent. No API docs needed.

Examples:
- "Allow curl to hit api.github.com, read-only"
- "Give claude full access to api.anthropic.com"
- "Let /usr/bin/myapp talk to internal-svc:8080 but only for reading"

This is sufficient for:
- **L4-only** policies (allow all traffic to host:port, no HTTP inspection)
- **Preset-based L7** policies (`read-only`, `read-write`, `full` on all paths)

For this tier, default to:
- `access: read-only` when the user says "read", "browse", "view", "query", "fetch"
- `access: read-write` when the user says "read-write", "create", "update" (but not "delete")
- `access: full` when the user says "full access", "everything", "unrestricted"
- L4-only (no `protocol`) when the user says "just allow it", "pass through", "no inspection"

### Moderate Tier (host + partial path knowledge)

The user knows some API paths but doesn't have full docs.

Examples:
- "Allow GET on /api/v1/models and POST on /api/v1/completions at integrate.api.nvidia.com"
- "Read-only on /repos/** at api.github.com, but also allow POST on /repos/*/issues"

Generate explicit `rules` for the known paths. If the user also wants broader access beyond the specific paths, combine with a catch-all rule or suggest a preset instead.

### Full Tier (complete API docs)

The user provides full API documentation. Accepted formats:

| Format | How to consume |
|--------|----------------|
| **URL** | Fetch with `WebFetch` and parse the endpoint list |
| **File path** | Read the file (OpenAPI JSON/YAML, markdown, etc.) |
| **Pasted text** | Parse inline from the conversation |
| **OpenAPI/Swagger spec** | Extract `paths` object for all method+path combinations |

From the API docs, build an **endpoint inventory** — a list of `(method, path, description)` tuples. Group them logically (e.g., by resource or tag). Then generate precise rules that allow only what the user's intent requires.

### Policy Intent

Regardless of tier, extract (or infer) these from the user's description:

| Aspect | What to identify | Required? |
|--------|-----------------|-----------|
| **Scope** | Which API host(s) and port(s) | Yes — always needed |
| **Access level** | Broad intent: read-only, read-write, full, or custom | Yes — ask if unclear |
| **Methods** | Specific HTTP methods to allow | Only for custom/fine-grained |
| **Paths** | Specific URL paths or patterns | Only for custom/fine-grained |
| **Enforcement** | `enforce` or `audit`? Default to `enforce`. | No — has a default |
| **Binary** | Which binary/process should have access | Yes — ask if not stated |

If the host and access level are clear but binaries are not specified, ask the user which binary or process will be making the requests. Suggest common defaults like `/usr/bin/curl`, `/usr/local/bin/claude`, etc.

## Step 2: Refine Scope (Clarification Loop)

Before generating the policy, **proactively ask clarifying questions** to help the user scope the policy down as narrowly as possible. The goal is the most restrictive policy that still satisfies the user's needs.

### Required Clarifications

Always ask about these if the user hasn't already specified them:

| Missing info | Question to ask |
|-------------|----------------|
| **Binary** not specified | "Which binary or process will make these requests? (e.g., `/usr/bin/curl`, `/usr/local/bin/claude`)" |
| **Port** not specified | "Which port does this API use? (443 for HTTPS is typical)" |
| **Enforcement** not stated | "Should policy violations be blocked (`enforce`) or just logged for review (`audit`)? I'll default to `enforce` if you're not sure." |

### Scoping-Down Questions

Ask these when the user's intent is broad and more specificity is possible:

| User says | Ask to narrow |
|-----------|--------------|
| "Full access" / "allow everything" | "Do you actually need DELETE access, or would read-write (everything except DELETE) be enough?" |
| "Allow access to api.example.com" (no method/path detail) | "Do you know which specific API paths or operations you need? If so, I can lock the policy down to just those. Otherwise I'll use a broad preset." |
| L4-only / "just pass it through" | "L4-only means the proxy won't inspect HTTP traffic at all — any method and path will be allowed. Are you sure you don't want at least read-only or read-write restriction?" |
| Wildcard binary (`/usr/bin/*`) | "A wildcard binary pattern means any binary in that directory can use this policy. Can you narrow it to specific binaries?" |
| Multiple hosts in one policy | "Do all of these hosts need the same access level? If some need tighter restrictions, I can split them into separate policies." |
| `access: full` with `enforcement: audit` | "Full access in audit mode means nothing is actually restricted — all traffic flows through and violations are only logged. Is that intentional, or did you want to enforce restrictions?" |
| `**` path glob on all rules | "Using `**` on all paths allows any URL path. Do you know the specific API path prefixes you need (e.g., `/api/v1/`)?" |
| Private/internal IP destination | "Does this service resolve to a private IP (10.x, 172.16.x, 192.168.x)? If so, you'll need `allowed_ips` to permit access — what CIDR range should be allowed?" |

### Auto-Discovery of API Docs for Well-Known Services

When the user mentions a recognizable API host but hasn't provided docs, and the current tier is **Minimal**, attempt to upgrade to **Full** by searching for the API documentation online.

**When to trigger:**
- The host is a well-known public API (e.g., `api.github.com`, `api.anthropic.com`, `api.openai.com`, `integrate.api.nvidia.com`, `api.stripe.com`, `api.slack.com`, `api.gitlab.com`)
- The user has NOT already provided API docs
- The user has NOT explicitly asked for a broad preset ("just read-only, nothing fancy")

**How to do it:**
1. Tell the user: "I can look up the REST API docs for [service] to help generate a more precise policy. Want me to do that?"
2. If the user agrees (or hasn't declined), search for the docs:
   - Use `WebSearch` with a query like `"[service name] REST API documentation endpoints"` or `"[service name] OpenAPI spec"`
   - Look for official documentation URLs in the results
3. Fetch the docs page with `WebFetch` and extract the endpoint inventory (method + path pairs)
4. Use the discovered endpoints to offer tighter scoping: "I found [N] endpoints in the [service] API. Based on your intent, I can narrow the policy to just [subset]. Want me to do that, or keep the broader preset?"

**When to skip:**
- The user explicitly asked for a broad preset or said "don't bother with docs"
- The API is internal, private, or not publicly documented
- The host is not recognizable as a well-known service
- A previous search attempt for this host returned no useful results

**Graceful fallback:** If the search doesn't return usable API docs (results are irrelevant, docs are behind authentication, the page is too large to parse), fall back to the current tier without stalling. Say: "I couldn't find usable API docs for [host], so I'll generate the policy using a [preset/L4] approach. You can always provide docs later to tighten it."

### When the User Can't Narrow Further

If the user confirms the policy must stay broad (they don't know the paths, need genuinely broad access, etc.), **accept it but flag the breadth**. Do not block policy generation — just make sure the warnings are visible in the output (see Step 6).

### Iteration

You may need to go back and forth a few times. Keep the loop tight:
1. Ask one batch of clarifying questions (group related questions together)
2. Update your understanding based on the answer
3. If the answer reveals further scoping opportunities, ask a follow-up
4. Stop when the user confirms the scope or says to proceed

**Do not over-interrogate.** If the user has given a clear, specific request, skip clarification and go straight to generation. Only ask when there is genuine ambiguity or an opportunity to meaningfully reduce the attack surface.

## Step 3: Read the Policy Schema

Read the full policy schema reference:

```
Read architecture/security-policy.md
```

Key sections to reference:
- **Full YAML Policy Schema** — top-level structure
- **`network_policies`** — rule structure
- **`NetworkEndpoint`** fields — host, port, protocol, tls, enforcement, access, rules, allowed_ips
- **`L7Rule` / `L7Allow`** — method + path matching
- **Access Presets** — `read-only`, `read-write`, `full`
- **Private IP Access via `allowed_ips`** — CIDR allowlist for private IP space
- **Validation Rules** — what combinations are valid/invalid

Also read the example policy for real-world patterns. The default policy is baked into the community base image (`ghcr.io/nvidia/openshell-community/sandboxes/base:latest`). For reference, consult the policy schema documentation:

```
Read architecture/security-policy.md
```

## Step 4: Choose Policy Shape

Follow this decision tree based on the detail tier and user intent:

```
Is L7 inspection needed?
├─ No (user wants pass-through / "just allow it")
│   └─ Generate L4-only policy (no protocol, no tls, no rules/access)
│
└─ Yes (user wants method/path control)
    │
    ├─ Does a preset match the intent exactly?
    │   ├─ Read-only (GET, HEAD, OPTIONS) → access: read-only
    │   ├─ Read-write (no DELETE)          → access: read-write
    │   └─ Everything                      → access: full
    │
    └─ No preset fits (specific paths, mixed broad+narrow, exclude certain paths)
        └─ Build explicit rules list
            └─ Requires either known paths from the user or full API docs
```

**Principle**: always choose the simplest representation that satisfies the intent. A preset is preferable to explicit rules when it covers the use case.

### TLS Decision

| API host port | TLS setting |
|--------------|-------------|
| Port 443 (HTTPS) and L7 rules/preset needed | `tls: terminate` (required for inspection) |
| Port 443 (HTTPS) and L4-only | Omit `tls` (passthrough, no L7) |
| Non-443 (HTTP) | Omit `tls` |

**Critical**: `protocol: rest` on port 443 without `tls: terminate` will not work — the proxy cannot inspect encrypted traffic. Always set `tls: terminate` when combining port 443 with L7 rules.

### Mapping Paths to Glob Patterns (when building explicit rules)

Only needed for the **Moderate** and **Full** tiers. Translate API path parameters to glob patterns:

| API path | Glob pattern |
|----------|-------------|
| `/repos/{owner}/{repo}` | `/repos/*/*` |
| `/repos/{owner}/{repo}/issues` | `/repos/*/issues` |
| `/repos/{owner}/{repo}/issues/{id}` | `/repos/*/issues/*` |
| `/api/v1/models/{model_id}/versions/{version}` | `/api/v1/models/*/versions/*` |
| All sub-paths under `/api/v1/` | `/api/v1/**` |

Remember: `*` does not cross `/` boundaries. Use `**` for recursive matching across path segments.

### Building the Explicit Rules List

For each allowed operation, create an `allow` entry:

```yaml
rules:
  - allow:
      method: GET
      path: "/api/v1/models/*"
  - allow:
      method: POST
      path: "/api/v1/completions"
```

Use the most specific pattern that covers the intent. Prefer narrow globs over `**` when the API structure is known.

## Step 5: Generate the Policy

### Output Format

Generate a complete `network_policies` entry. Use this template:

```yaml
network_policies:
  <policy_key>:
    name: <policy_key>
    endpoints:
      - host: <api_host>
        port: <port>
        protocol: rest          # Required for L7 inspection
        tls: terminate          # Required for HTTPS + L7
        enforcement: enforce    # or audit
        # Use ONE of: access OR rules (never both)
        access: <preset>        # read-only | read-write | full
        # OR
        rules:
          - allow:
              method: <METHOD>
              path: "<glob_pattern>"
        # Optional: allow private IP destinations (CIDR or exact IP)
        # allowed_ips:
        #   - "10.0.5.0/24"
    binaries:
      - { path: <binary_path> }
```

### Deny Rules

Use `deny_rules` to block specific dangerous operations while allowing broad access. Deny rules are evaluated after allow rules and take precedence. This is the inverse of the `rules` approach — instead of enumerating every allowed operation, you grant broad access and block a small set of dangerous ones.

```yaml
# Example: Allow full access to GitHub but block admin operations
github_api:
  name: github_api
  endpoints:
    - host: api.github.com
      port: 443
      protocol: rest
      enforcement: enforce
      access: read-write
      deny_rules:
        - method: POST
          path: "/repos/*/pulls/*/reviews"
        - method: PUT
          path: "/repos/*/branches/*/protection"
        - method: "*"
          path: "/repos/*/rulesets"
  binaries:
    - { path: /usr/bin/curl }
```

Deny rules support the same matching capabilities as allow rules: `method`, `path`, `command` (SQL), and `query` parameter matchers. When generating policies, prefer deny rules when the user needs broad access with a small set of blocked operations — it produces a shorter, more maintainable policy than enumerating 60+ allow rules.

### Private IP Destinations

When the endpoint resolves to a private IP (RFC 1918), the proxy's SSRF protection blocks the connection by default. Use `allowed_ips` to selectively allow specific private IP ranges:

- **Host + allowlist**: `host` + `allowed_ips` — domain must resolve to an IP in the allowlist
- **Hostless allowlist**: `allowed_ips` only (no `host`) — any domain on the port is allowed if it resolves to an IP in the allowlist

Loopback (`127.0.0.0/8`) and link-local (`169.254.0.0/16`) are **always blocked** regardless of `allowed_ips`.

```yaml
# Example: Allow access to internal service at a known private IP range
internal_api:
  name: internal_api
  endpoints:
    - host: api.internal.corp
      port: 8080
      allowed_ips:
        - "10.0.5.0/24"
  binaries:
    - { path: /usr/bin/curl }
```

### Policy Key Naming

Use descriptive snake_case keys: `github_api`, `nvidia_inference`, `internal_service_readonly`.

### Multiple Endpoints

If the user needs access to multiple hosts or the same host with different rules, either:

1. **Same policy** — multiple entries in `endpoints` if the binary set is the same
2. **Separate policies** — different policy keys if the binary sets differ

## Step 6: Validate and Warn

Before presenting the policy to the user, verify correctness **and** flag breadth concerns.

### Hard Errors (would block sandbox startup)

- [ ] `rules` and `access` are NOT both present on the same endpoint
- [ ] If `protocol` is set, either `rules` or `access` is also present
- [ ] If `tls: terminate` is set, `protocol` is also set
- [ ] `rules` list is not empty when present
- [ ] If `protocol: sql`, `enforcement` is not `enforce`

### Schema Warnings (log-only, but should be fixed)

- [ ] `protocol: rest` on port 443 should have `tls: terminate`
- [ ] HTTP methods are standard: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, or `*`

### Structural Checks

- [ ] Every policy has `name`, `endpoints`, and `binaries`
- [ ] Every endpoint has `host` and `port`
- [ ] Every binary has `path`
- [ ] Policy key matches `name` field

### Breadth Warnings

Evaluate the generated policy for overly broad access and **include warnings in the output to the user**. These do not block generation, but the user must see them.

| Condition | Warning to show |
|-----------|----------------|
| **L4-only** (no `protocol`) | "This policy allows all HTTP methods and paths without inspection. The proxy will only check host:port and binary identity. Consider adding `protocol: rest` with a preset if you want method-level control." |
| **`access: full`** | "This policy allows all HTTP methods (including DELETE) on all paths. If you don't need DELETE, `read-write` is safer. If you only need to read, `read-only` is the most restrictive option." |
| **`access: full` + `enforcement: audit`** | "Full access in audit mode provides no actual restriction — all traffic flows through. This is effectively a monitoring-only policy." |
| **`access: read-write`** when user hasn't confirmed write need | "This policy allows POST, PUT, and PATCH on all paths. If you only need to read data, `read-only` is more restrictive." |
| **Wildcard binary** (`*` or `**` in binary path) | "This policy allows any binary matching the glob pattern. A compromised or unexpected binary in that directory could use this policy. Consider listing specific binary paths." |
| **`**` path glob** on all explicit rules | "All rules use `**` path patterns, which match any URL path. This is equivalent to a preset — consider using `access: read-only` (or similar) for clarity, or narrowing paths if you know the API structure." |
| **Multiple broad endpoints** in one policy | "This policy grants the same broad access to N different hosts. If any of these hosts needs tighter restrictions later, you'll need to split the policy." |
| **Hostless `allowed_ips`** (no `host` field) | "This endpoint has no `host` — any domain resolving to the allowed IP range on this port will be permitted. Consider adding a `host` field to restrict which domains can use this allowlist." |
| **Broad CIDR** in `allowed_ips` (e.g., `10.0.0.0/8`) | "This `allowed_ips` entry covers a very broad range. Consider narrowing to a specific subnet (e.g., `10.0.5.0/24`) to minimize exposure." |

Format breadth warnings clearly in the output, e.g.:

```
⚠️ Breadth warning: This policy uses `access: full`, which allows all HTTP
methods (including DELETE) on all paths. If you don't need DELETE, consider
using `read-write` instead.
```

If there are no breadth warnings, say so explicitly: "No breadth concerns — this policy is well-scoped."

## Step 7: Determine Output Mode

The policy needs to go somewhere. Determine which mode applies:

| Signal | Mode |
|--------|------|
| User names an existing policy file (e.g., "add to my-sandbox-policy.yaml") | **Update existing file** |
| User says "update my policy", "add this to my policy file" | **Update existing file** — ask which file to update |
| User asks to modify an existing policy rule by name | **Update existing file** — edit the named policy in place |
| User says "create a new policy file" or names a file that doesn't exist | **Create new file** |
| No file context given | **Present only** — show the YAML and ask if the user wants it written to a file |

### Mode A: Update an Existing Policy File

1. **Read the existing file** to understand current state:
   - What policies already exist under `network_policies`
   - What the `filesystem_policy`, `landlock`, and `process` sections look like
   - Whether the file uses compact (`{ host: ..., port: ... }`) or expanded YAML style

2. **Check for conflicts**:
   - Does a policy with the same key already exist? If so, ask the user whether to **replace** it, **merge** new endpoints/binaries into it, or use a different key.
   - Does an existing policy already cover the same host:port? Warn the user — overlapping endpoint coverage across policies causes OPA evaluation errors (complete rule conflict).

3. **Apply the change**:
   - **Adding a new policy**: Insert the new policy block under `network_policies`, maintaining the file's existing indentation and style.
   - **Modifying an existing policy**: Edit the specific policy in place — add/remove endpoints, change access presets, update rules, add binaries, etc.
   - **Removing a policy**: Delete the policy block if the user asks.

4. **Preserve everything else**: Do not modify `filesystem_policy`, `landlock`, `process`, or other policies unless the user explicitly asks.

### Mode B: Create a New Policy File

Generate a complete, standalone policy file. Use the full schema scaffolding:

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  # <generated policies go here>
```

The `filesystem_policy`, `landlock`, and `process` sections above are sensible defaults. Tell the user these are defaults and may need adjustment for their environment. Cluster inference is configured separately through `openshell cluster inference set/get`. The generated `network_policies` block is the primary output.

If the user provides a file path, write to it. Otherwise, ask where to place it. A common convention is a project-local policy file (e.g., `sandbox-policy.yaml`) passed to `openshell sandbox create --policy <path>` or set via the `OPENSHELL_SANDBOX_POLICY` env var.

### Mode C: Present Only (no file write)

Show the generated policy YAML with:

1. **Summary** — what the policy allows and denies, in plain language
2. **The YAML** — the complete `network_policies` block, ready to paste
3. **Integration guidance**:
   - Save to a local file and pass via `openshell sandbox create --policy <path>` or set `OPENSHELL_SANDBOX_POLICY=<path>`
   - For production: configure via the gateway
4. **Caveats** — any assumptions made, anything the user should verify

## Step 8: Confirm and Refine

After presenting or applying the policy, ask if the user wants to:
- Tighten or loosen any rules
- Add more endpoints or binaries
- Switch between enforce/audit mode
- Move from a preset to explicit rules (or vice versa)
- Apply the policy to a file (if presented only)
- Create additional policies for other APIs

## Quick Reference: Common Patterns

### L4-Only (no HTTP inspection)

```yaml
my_api:
  name: my_api
  endpoints:
    - { host: api.example.com, port: 443 }
  binaries:
    - { path: /usr/bin/curl }
```

### HTTPS API with Read-Only Preset

```yaml
my_api_readonly:
  name: my_api_readonly
  endpoints:
    - host: api.example.com
      port: 443
      protocol: rest
      tls: terminate
      enforcement: enforce
      access: read-only
  binaries:
    - { path: /usr/bin/curl }
```

### HTTPS API with Explicit Rules

```yaml
my_api_custom:
  name: my_api_custom
  endpoints:
    - host: api.example.com
      port: 443
      protocol: rest
      tls: terminate
      enforcement: enforce
      rules:
        - allow:
            method: GET
            path: "/api/v1/**"
        - allow:
            method: POST
            path: "/api/v1/data"
  binaries:
    - { path: /usr/bin/curl }
    - { path: /usr/local/bin/myapp }
```

### HTTP (non-TLS) Internal API

```yaml
internal_svc:
  name: internal_svc
  endpoints:
    - host: api.internal.svc
      port: 8080
      protocol: rest
      enforcement: enforce
      rules:
        - allow:
            method: GET
            path: "/health"
        - allow:
            method: POST
            path: "/api/v1/jobs"
  binaries:
    - { path: /usr/bin/curl }
```

### Private IP Access (Host + Allowlist)

```yaml
internal_db:
  name: internal_db
  endpoints:
    - host: db.internal.corp
      port: 5432
      allowed_ips:
        - "10.0.5.0/24"
  binaries:
    - { path: /usr/bin/curl }
```

### Private IP Access (Hostless — Any Domain in Range)

```yaml
private_services:
  name: private_services
  endpoints:
    - port: 8080
      allowed_ips:
        - "10.0.5.0/24"
        - "10.0.6.0/24"
  binaries:
    - { path: /usr/bin/curl }
```

## Additional Resources

- Full policy schema: [architecture/security-policy.md](../../../architecture/security-policy.md)
- Default policy: baked into the community base image (`ghcr.io/nvidia/openshell-community/sandboxes/base:latest`)
- Rego evaluation rules: [sandbox-policy.rego](../../../crates/openshell-sandbox/data/sandbox-policy.rego)
- For translation examples from real API docs, see [examples.md](examples.md)
