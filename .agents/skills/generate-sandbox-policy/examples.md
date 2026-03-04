# Policy Generation Examples

Examples organized by detail tier — from minimal (just host + intent) to full (complete API docs).

---

## Minimal Tier Examples (host + intent, no API docs)

### Example M1: L4 Pass-Through

**User**: "Let claude talk to api.anthropic.com and statsig.anthropic.com, just let everything through."

No API docs needed. No L7 inspection.

```yaml
network_policies:
  claude_anthropic:
    name: claude_anthropic
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
```

No `protocol`, `tls`, `rules`, or `access` — this is pure L4 (host:port + binary identity check).

---

### Example M2: Read-Only Preset Against a Known Host

**User**: "I need curl to be able to read from api.github.com but not modify anything."

No API docs needed — `read-only` preset covers this.

```yaml
network_policies:
  github_readonly:
    name: github_readonly
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

Allows GET, HEAD, OPTIONS on all paths. Blocks POST, PUT, PATCH, DELETE.

---

### Example M3: Full Access Preset

**User**: "Give opencode unrestricted access to integrate.api.nvidia.com."

```yaml
network_policies:
  nvidia_api:
    name: nvidia_api
    endpoints:
      - host: integrate.api.nvidia.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - { path: /usr/local/bin/opencode }
```

Allows all HTTP methods on all paths.

---

### Example M4: Read-Write (No Deletes) Against an Internal Service

**User**: "My app at /app/bin/worker needs to talk to data-svc.internal on port 8080. It should be able to create and update records but not delete anything. Audit only for now."

```yaml
network_policies:
  data_service:
    name: data_service
    endpoints:
      - host: data-svc.internal
        port: 8080
        protocol: rest
        enforcement: audit
        access: read-write
    binaries:
      - { path: /app/bin/worker }
```

Allows GET, HEAD, OPTIONS, POST, PUT, PATCH. Blocks DELETE. Audit mode logs violations without blocking.

---

### Example M5: Multiple Hosts, Same Access Level

**User**: "Allow curl to read from both api.github.com and api.gitlab.com."

```yaml
network_policies:
  code_hosting_readonly:
    name: code_hosting_readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
      - host: api.gitlab.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
```

Same preset applied to multiple hosts in one policy because the binary set is the same.

---

### Example M6: Auto-Discovery Upgrades Minimal to Full

**User**: "Allow curl to access the OpenAI API for inference."

**Agent workflow**:

1. Recognize `api.openai.com` as a well-known service
2. Ask: "I can look up OpenAI's REST API docs to generate a more precise policy. Want me to do that, or should I use a broad preset?"
3. User says: "Yeah go ahead"
4. `WebSearch` for "OpenAI REST API documentation endpoints"
5. `WebFetch` the docs page, extract endpoints:
   - `POST /v1/chat/completions`
   - `POST /v1/embeddings`
   - `GET /v1/models`
   - `GET /v1/models/{model}`
   - `POST /v1/images/generations`
   - ...etc
6. Ask: "I found these endpoints. You said 'inference' — do you need just chat completions, or also embeddings, images, and audio?"
7. User says: "Just chat completions and listing models"
8. Generate a tightly scoped policy:

```yaml
network_policies:
  openai_inference:
    name: openai_inference
    endpoints:
      - host: api.openai.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: "/v1/chat/completions"
          - allow:
              method: GET
              path: "/v1/models"
          - allow:
              method: GET
              path: "/v1/models/*"
    binaries:
      - { path: /usr/bin/curl }
```

Without auto-discovery, this would have been `access: full` or `access: read-write`. The search enabled a much tighter policy.

---

### Example M7: Auto-Discovery Fallback

**User**: "Let curl talk to api.mycorp.internal on port 8080, read-only."

**Agent workflow**:

1. `api.mycorp.internal` is not a well-known public service — skip auto-discovery
2. Generate using the `read-only` preset directly (no search attempted)

---

## Moderate Tier Examples (host + partial path knowledge)

### Example T1: Known Paths Without Full Docs

**User**: "Allow GET on /v1/models and POST on /v1/chat/completions at integrate.api.nvidia.com for curl."

User knows specific paths but didn't provide full API docs.

```yaml
network_policies:
  nvidia_inference:
    name: nvidia_inference
    endpoints:
      - host: integrate.api.nvidia.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/models"
          - allow:
              method: GET
              path: "/v1/models/*"
          - allow:
              method: POST
              path: "/v1/chat/completions"
    binaries:
      - { path: /usr/bin/curl }
```

Note: added `/v1/models/*` alongside `/v1/models` since listing models and getting a specific model are both common read operations.

---

### Example T2: Broad Read + Targeted Write

**User**: "Read-only across all of api.github.com, but also allow creating issues on any repo."

The user knows the issue-creation path but doesn't have full docs. Use explicit rules to combine the broad read access with the specific write path.

```yaml
network_policies:
  github_with_issues:
    name: github_with_issues
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/**"
          - allow:
              method: HEAD
              path: "/**"
          - allow:
              method: OPTIONS
              path: "/**"
          - allow:
              method: POST
              path: "/repos/*/issues"
    binaries:
      - { path: /usr/bin/curl }
```

Cannot use `access: read-only` here because we also need POST on one path. The explicit rules replicate the read-only preset and add the targeted write.

---

## Full Tier Examples (complete API docs)

### Example 1: GitHub REST API — Read-Only Access

### Input: API Docs (excerpt)

```
GitHub REST API v3 — https://api.github.com

Endpoints:
  GET    /repos/{owner}/{repo}                  Get a repository
  GET    /repos/{owner}/{repo}/issues            List issues
  POST   /repos/{owner}/{repo}/issues            Create an issue
  PATCH  /repos/{owner}/{repo}/issues/{number}   Update an issue
  DELETE /repos/{owner}/{repo}                   Delete a repository
  GET    /repos/{owner}/{repo}/pulls             List pull requests
  POST   /repos/{owner}/{repo}/pulls             Create a pull request
  PUT    /repos/{owner}/{repo}/pulls/{number}/merge  Merge a pull request
  GET    /user                                   Get authenticated user
  GET    /orgs/{org}/repos                       List org repos
```

### Input: User Intent

> "I want read-only access to GitHub's API — browsing repos, issues, and PRs but no creating, updating, or deleting anything. This is for curl."

### Analysis

- Scope: `api.github.com:443` (HTTPS)
- Methods: GET, HEAD, OPTIONS only
- Paths: All paths (user wants to browse freely)
- This maps exactly to the `read-only` preset
- Port 443 + L7 rules → needs `tls: terminate`

### Output

```yaml
network_policies:
  github_api_readonly:
    name: github_api_readonly
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

**What this allows**: GET, HEAD, OPTIONS on any path.
**What this denies**: POST, PUT, PATCH, DELETE on any path.

---

## Example 2: NVIDIA NIM API — Specific Inference Endpoints

### Input: API Docs (excerpt)

```
NVIDIA NIM API — https://integrate.api.nvidia.com

Endpoints:
  POST   /v1/chat/completions          Chat completion inference
  POST   /v1/completions               Text completion inference
  POST   /v1/embeddings                Generate embeddings
  GET    /v1/models                    List available models
  GET    /v1/models/{model_id}         Get model details
  POST   /v1/images/generations        Generate images
  POST   /v1/audio/transcriptions      Transcribe audio
  DELETE /v1/fine_tuning/jobs/{id}     Cancel fine-tuning job
  POST   /v1/fine_tuning/jobs          Create fine-tuning job
```

### Input: User Intent

> "Allow the sandbox to call chat completions and list models, but nothing else. The binary is /usr/bin/curl and also /usr/local/bin/opencode. Enforce strictly."

### Analysis

- Scope: `integrate.api.nvidia.com:443`
- Methods: POST on `/v1/chat/completions`, GET on `/v1/models` and `/v1/models/*`
- No preset fits — need explicit rules
- Port 443 + L7 → `tls: terminate`
- Two binaries

### Output

```yaml
network_policies:
  nvidia_inference:
    name: nvidia_inference
    endpoints:
      - host: integrate.api.nvidia.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/v1/models"
          - allow:
              method: GET
              path: "/v1/models/*"
          - allow:
              method: POST
              path: "/v1/chat/completions"
    binaries:
      - { path: /usr/bin/curl }
      - { path: /usr/local/bin/opencode }
```

**What this allows**: GET `/v1/models`, GET `/v1/models/{id}`, POST `/v1/chat/completions`.
**What this denies**: All other method+path combinations (embeddings, images, fine-tuning, etc.).

---

## Example 3: Internal Microservice — Read-Write Without Delete

### Input: API Docs (excerpt)

```
Internal Data Service — http://data-svc.internal:8080

Endpoints:
  GET    /api/v1/datasets                List datasets
  POST   /api/v1/datasets                Create dataset
  GET    /api/v1/datasets/{id}           Get dataset
  PUT    /api/v1/datasets/{id}           Update dataset
  DELETE /api/v1/datasets/{id}           Delete dataset
  GET    /api/v1/datasets/{id}/records   List records
  POST   /api/v1/datasets/{id}/records   Create record
  DELETE /api/v1/datasets/{id}/records/{rid}  Delete record
  GET    /health                         Health check
```

### Input: User Intent

> "Read-write access — create and update datasets and records, but never delete anything. Start in audit mode so we can verify before enforcing."

### Analysis

- Scope: `data-svc.internal:8080` (HTTP, no TLS needed)
- The `read-write` preset covers GET, HEAD, OPTIONS, POST, PUT, PATCH — but not DELETE. Exactly what the user wants.
- Audit mode requested

### Output

```yaml
network_policies:
  data_service:
    name: data_service
    endpoints:
      - host: data-svc.internal
        port: 8080
        protocol: rest
        enforcement: audit
        access: read-write
    binaries:
      - { path: /usr/bin/curl }
```

**What this allows**: GET, HEAD, OPTIONS, POST, PUT, PATCH on all paths.
**What this denies**: DELETE on any path.
**Note**: `enforcement: audit` means denials are logged but traffic still flows. Switch to `enforce` once verified.

---

## Example 4: OpenAPI Spec — Selective Access

### Input: OpenAPI Spec (partial)

```yaml
openapi: 3.0.0
info:
  title: Project Management API
  version: 1.0.0
servers:
  - url: https://pm-api.example.com
paths:
  /projects:
    get:
      summary: List projects
    post:
      summary: Create project
  /projects/{id}:
    get:
      summary: Get project
    put:
      summary: Update project
    delete:
      summary: Delete project
  /projects/{id}/tasks:
    get:
      summary: List tasks
    post:
      summary: Create task
  /projects/{id}/tasks/{taskId}:
    get:
      summary: Get task
    put:
      summary: Update task
    delete:
      summary: Delete task
  /projects/{id}/members:
    get:
      summary: List members
    post:
      summary: Add member
    delete:
      summary: Remove member
  /admin/users:
    get:
      summary: List users (admin)
    delete:
      summary: Delete user (admin)
```

### Input: User Intent

> "Allow full CRUD on projects and tasks, read-only on members, and block all admin endpoints. Use /app/bin/pm-cli as the binary."

### Analysis

- Scope: `pm-api.example.com:443`
- Projects: GET, POST, PUT, DELETE on `/projects` and `/projects/*`
- Tasks: GET, POST, PUT, DELETE on `/projects/*/tasks` and `/projects/*/tasks/*`
- Members: GET only on `/projects/*/members`
- Admin: No rules = denied by default
- Port 443 + L7 → `tls: terminate`

### Output

```yaml
network_policies:
  project_management:
    name: project_management
    endpoints:
      - host: pm-api.example.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          # Projects — full CRUD
          - allow:
              method: GET
              path: "/projects"
          - allow:
              method: POST
              path: "/projects"
          - allow:
              method: GET
              path: "/projects/*"
          - allow:
              method: PUT
              path: "/projects/*"
          - allow:
              method: DELETE
              path: "/projects/*"
          # Tasks — full CRUD
          - allow:
              method: GET
              path: "/projects/*/tasks"
          - allow:
              method: POST
              path: "/projects/*/tasks"
          - allow:
              method: GET
              path: "/projects/*/tasks/*"
          - allow:
              method: PUT
              path: "/projects/*/tasks/*"
          - allow:
              method: DELETE
              path: "/projects/*/tasks/*"
          # Members — read-only
          - allow:
              method: GET
              path: "/projects/*/members"
    binaries:
      - { path: /app/bin/pm-cli }
```

**What this allows**: Full CRUD on projects and tasks, GET-only on members.
**What this denies**: All admin endpoints, DELETE/POST/PUT on members, any unlisted paths.

---

## Example 5: Mixed L4 and L7 Policy

### Input: User Intent

> "I need claude to access Anthropic APIs (just let everything through, no inspection needed), and also access our internal docs API at docs.internal:8080 but only for reading. The docs API is HTTP so no TLS."

### Analysis

- Anthropic API: L4-only (no inspection), standard claude binary
- Internal docs: L7 with read-only, HTTP so no TLS config needed
- Two separate policies because different binaries

### Output

```yaml
network_policies:
  claude_anthropic:
    name: claude_anthropic
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }

  internal_docs_readonly:
    name: internal_docs_readonly
    endpoints:
      - host: docs.internal
        port: 8080
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/local/bin/claude }
```

**Note**: The first policy has no `protocol` field — this means L4-only (host:port check, no HTTP inspection). The second policy has `protocol: rest` so every HTTP request is inspected.

---

## Example 6: Wildcard Binary Patterns

### Input: User Intent

> "Any binary under /usr/local/bin/ should be able to hit our metrics endpoint at metrics.corp.com:443, but only GET /metrics and GET /api/v1/query. Enforce it."

### Output

```yaml
network_policies:
  corp_metrics:
    name: corp_metrics
    endpoints:
      - host: metrics.corp.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/metrics"
          - allow:
              method: GET
              path: "/api/v1/query"
    binaries:
      - { path: "/usr/local/bin/*" }
```

**Note**: The `*` glob in the binary path matches any binary directly inside `/usr/local/bin/` but does not cross `/` boundaries. Use `/usr/local/**` to match recursively.

---

## File Operation Examples (update existing / create new)

## Private IP Access Examples (allowed_ips)

### Example P1: Internal Service with Known IP Range

**User**: "Allow curl to reach our internal API at api.internal.corp on port 8080. It resolves to 10.0.5.x addresses."

The user knows the service resolves to private IPs. Use `allowed_ips` to permit the specific subnet.

```yaml
network_policies:
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

**What this allows**: Connections to `api.internal.corp:8080` when DNS resolves to any IP in `10.0.5.0/24`.
**What this blocks**: Connections if the domain resolves outside the allowlist, or to any loopback/link-local address.

---

### Example P2: Multiple Internal Subnets

**User**: "Our microservices are spread across 10.0.5.x and 10.0.6.x on port 8080. Let opencode reach any of them without listing every hostname."

Use a hostless endpoint with `allowed_ips` — any domain on port 8080 is allowed if it resolves to an IP in the listed ranges.

```yaml
network_policies:
  private_services:
    name: private_services
    endpoints:
      - port: 8080
        allowed_ips:
          - "10.0.5.0/24"
          - "10.0.6.0/24"
    binaries:
      - { path: /usr/local/bin/opencode }
```

**What this allows**: Any hostname on port 8080 whose DNS resolves to `10.0.5.0/24` or `10.0.6.0/24`.
**What this blocks**: Any hostname resolving outside these ranges, or to loopback/link-local addresses.

**Note**: No `host` field means any domain name is accepted — only the resolved IP is checked. This is broader; use `host` when you know the specific hostname.

---

### Example P3: Private IP with L7 Inspection

**User**: "Allow read-only REST access to db-proxy.internal on port 3128. It's at 172.16.1.50."

Combine `allowed_ips` with L7 inspection for fine-grained control over a private service.

```yaml
network_policies:
  db_proxy_readonly:
    name: db_proxy_readonly
    endpoints:
      - host: db-proxy.internal
        port: 3128
        protocol: rest
        enforcement: enforce
        access: read-only
        allowed_ips:
          - "172.16.1.50"
    binaries:
      - { path: /usr/bin/curl }
```

**What this allows**: GET, HEAD, OPTIONS on any path to `db-proxy.internal:3128`, only if it resolves to `172.16.1.50`.
**What this blocks**: POST, PUT, PATCH, DELETE, and connections resolving to any other IP.

---

### Example P4: Exact IP (No CIDR)

**User**: "Allow curl to reach exactly 10.0.5.20 on port 9090 via metrics.internal."

```yaml
network_policies:
  metrics_internal:
    name: metrics_internal
    endpoints:
      - host: metrics.internal
        port: 9090
        allowed_ips:
          - "10.0.5.20"
    binaries:
      - { path: /usr/bin/curl }
```

An exact IP is treated as `/32` — only that specific address is permitted.

---

## File Operation Examples (update existing / create new)

### Example F1: Add a New Policy to an Existing File

**User**: "Add read-only access to api.github.com for curl to my dev-sandbox-policy.yaml"

**Agent workflow**:

1. Read `dev-sandbox-policy.yaml`
2. Check that no existing policy already covers `api.github.com:443` — if one does, warn about overlap
3. Check that the key `github_readonly` doesn't already exist
4. Insert the new policy under `network_policies`:

```yaml
# Existing policies remain untouched...

  github_readonly:
    name: github_readonly
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

The agent uses `StrReplace` to insert after the last existing policy in the `network_policies` block. All other sections (`filesystem_policy`, `landlock`, `process`, `inference`) are untouched.

---

### Example F2: Modify an Existing Policy (Add an Endpoint)

**User**: "Add sentry.io to the claude_code policy in dev-sandbox-policy.yaml"

**Agent workflow**:

1. Read `dev-sandbox-policy.yaml`
2. Find the `claude_code` policy
3. Check that `sentry.io:443` isn't already listed in its endpoints
4. Add the new endpoint to the existing `endpoints` list:

Before:
```yaml
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
```

After:
```yaml
  claude_code:
    name: claude_code
    endpoints:
      - { host: api.anthropic.com, port: 443 }
      - { host: statsig.anthropic.com, port: 443 }
      - { host: sentry.io, port: 443 }
    binaries:
      - { path: /usr/local/bin/claude }
```

---

### Example F3: Modify an Existing Policy (Change Access Level)

**User**: "Switch the github_api_readonly policy to read-write"

**Agent workflow**:

1. Read the policy file
2. Find `github_api_readonly`
3. Replace `access: read-only` with `access: read-write`
4. Suggest renaming the key to `github_api_readwrite` for clarity (ask user)

---

### Example F4: Create a Brand-New Policy File

**User**: "Create a new policy file at sandbox-policy-staging.yaml with read-only access to api.github.com and full access to api.anthropic.com for claude"

**Agent workflow**:

1. No existing file — generate the full scaffolding with defaults
2. Populate `network_policies` with the two requested policies
3. Write the complete file:

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
  github_readonly:
    name: github_readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/local/bin/claude }

  anthropic_full:
    name: anthropic_full
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: full
    binaries:
      - { path: /usr/local/bin/claude }

inference:
  allowed_routes:
    - local
```

The agent notes that `filesystem_policy`, `landlock`, `process`, and `inference` are sensible defaults that may need adjustment.

---

### Example F5: Handle a Key Conflict

**User**: "Add an nvidia policy to dev-sandbox-policy.yaml"

**Agent workflow**:

1. Read `dev-sandbox-policy.yaml`
2. Find that a policy key `nvidia` already exists
3. **Ask the user**: "A policy named `nvidia` already exists. Do you want to replace it, add endpoints to it, or use a different name (e.g., `nvidia_inference_v2`)?"
4. Proceed based on the user's answer
