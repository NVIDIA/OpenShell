---
name: hindsight-memory
description: Give sandboxed agents persistent memory across sessions using Hindsight. Use to recall context before starting work, store learnings after completing tasks, and maintain continuity across ephemeral sandbox sessions. Trigger keywords - remember, recall, retain, memory, context, what did we learn, previous session, store knowledge, hindsight, persistent memory, cross-session context.
---

# Hindsight Memory

Give sandboxed agents persistent memory across ephemeral sandbox sessions using [Hindsight](https://github.com/vectorize-io/hindsight).

Sandboxes are isolated and disposable. When a sandbox is destroyed, everything the agent learned is lost. Hindsight solves this by providing a structured memory API that agents can call from inside the sandbox to recall past context and store new learnings.

## Overview

Hindsight is an agent memory system that provides long-term memory using biomimetic data structures. Memories are organized as:

- **World facts**: General knowledge ("The project uses ESLint with Airbnb config")
- **Experience facts**: Personal experiences ("Build failed when using Node 18, works with Node 20")
- **Mental models**: Consolidated knowledge synthesized from facts ("User prefers functional programming patterns")

This skill teaches agents when and how to use Hindsight memory from inside an OpenShell sandbox.

## Prerequisites

- The `hindsight` CLI must be installed in the sandbox image
- A Hindsight provider must be attached to the sandbox (see Setup)
- A memory bank must exist (the user provides the bank ID)

## Setup

### 1. Create the Hindsight Provider

The Hindsight provider injects `HINDSIGHT_API_KEY` and `HINDSIGHT_API_URL` into the sandbox.

```bash
# From existing environment variables
openshell provider create --name hindsight --type generic \
  --credential HINDSIGHT_API_KEY \
  --config HINDSIGHT_API_URL

# Or with explicit values
openshell provider create --name hindsight --type generic \
  --credential HINDSIGHT_API_KEY=hs-your-api-key \
  --config HINDSIGHT_API_URL=https://api.hindsight.vectorize.io
```

### 2. Create a Sandbox with Hindsight

Attach the provider and ensure the sandbox has network access to the Hindsight API:

```bash
openshell sandbox create \
  --provider hindsight \
  --policy sandbox-policy.yaml \
  -- claude
```

### 3. Configure the CLI Inside the Sandbox

On first use, create the Hindsight CLI config:

```bash
mkdir -p ~/.hindsight
cat > ~/.hindsight/config << 'EOF'
api_url = "${HINDSIGHT_API_URL}"
api_key = "${HINDSIGHT_API_KEY}"
EOF
chmod 600 ~/.hindsight/config
```

If the `hindsight` CLI is not available in the base image, install it:

```bash
curl -fsSL https://hindsight.vectorize.io/get-cli | bash
```

## Workflow 1: Recall Before Starting Work

**Always recall relevant context before starting any non-trivial task.** This is the most important workflow. Without it, the agent starts from zero every time.

```bash
# Recall context about the area you're about to work on
hindsight memory recall <bank-id> "authentication module architecture"

# Recall what went wrong last time
hindsight memory recall <bank-id> "issues encountered with database migrations"

# Recall team conventions
hindsight memory recall <bank-id> "coding standards and project conventions"

# Recall a specific person's preferences
hindsight memory recall <bank-id> "Alice preferences for code review"
```

### When to Recall

- Before starting any non-trivial task
- Before making implementation decisions
- When working in an unfamiliar area of the codebase
- When answering questions about the project
- When a previous sandbox session worked on the same topic

### Recall Options

```bash
# Higher budget for complex questions (more thorough search)
hindsight memory recall <bank-id> "query" --budget high

# Limit response size
hindsight memory recall <bank-id> "query" --max-tokens 4096

# Filter by fact type
hindsight memory recall <bank-id> "query" --fact-type world,experience

# JSON output for programmatic use
hindsight memory recall <bank-id> "query" -o json
```

## Workflow 2: Retain After Completing Work

**Store what you learned immediately after discovering it.** Do not wait until the end of the session. Sandboxes can be destroyed at any time.

```bash
# Store a project convention
hindsight memory retain <bank-id> "Project uses 2-space indentation with Prettier"

# Store a learning with context
hindsight memory retain <bank-id> "Build failed when using Node 18, works with Node 20" --context learnings

# Store a procedure
hindsight memory retain <bank-id> "Running integration tests requires Docker and POSTGRES_URL set" --context procedures

# Store a debugging outcome
hindsight memory retain <bank-id> "The auth timeout was caused by missing CONNECTION_POOL_SIZE env var, default of 5 was too low" --context debugging
```

### What to Store

| Category | Examples | Context Tag |
|----------|----------|-------------|
| Project conventions | Coding standards, branch naming, PR conventions | `conventions` |
| Procedures | Steps that completed a task, required env vars | `procedures` |
| Learnings | Bugs and solutions, what worked and what didn't | `learnings` |
| Architecture | Design decisions, component relationships | `architecture` |
| Team knowledge | Onboarding info, domain knowledge, pitfalls | `team` |
| Individual preferences | "Alice prefers explicit type annotations" | `preferences` |

### Retain Best Practices

1. **Store immediately** — do not batch. The sandbox could be destroyed.
2. **Be specific** — store "npm test requires --experimental-vm-modules flag" not "tests need a flag".
3. **Include outcomes** — store what worked AND what did not work.
4. **Use context tags** — they help with filtering during recall.
5. **Attribute preferences** — store "Alice prefers X" not "user prefers X".

## Workflow 3: Reflect for Synthesized Answers

Use `reflect` when you need Hindsight to synthesize an answer from multiple memories rather than returning raw recall results.

```bash
# Synthesize context for a task
hindsight memory reflect <bank-id> "How should I approach adding a new API endpoint based on past experience?"

# Get a summary
hindsight memory reflect <bank-id> "What do we know about the payment processing module?"

# Higher budget for complex synthesis
hindsight memory reflect <bank-id> "Summarize all architecture decisions" --budget high
```

## Workflow 4: Retain Files for Bulk Knowledge

When a sandbox session produces artifacts (logs, reports, investigation notes), retain the files directly:

```bash
# Retain a single file
hindsight memory retain-files <bank-id> investigation-notes.txt

# Retain a directory
hindsight memory retain-files <bank-id> ./reports/

# With context
hindsight memory retain-files <bank-id> debug-log.txt --context "debugging auth timeout issue"

# Background processing for large files
hindsight memory retain-files <bank-id> ./large-dataset/ --async
```

## Workflow 5: Cross-Sandbox Continuity

This is the core value of Hindsight in OpenShell. When a sandbox is destroyed and a new one is created, the agent can pick up where the previous session left off.

**Previous sandbox session:**

```bash
# Agent discovers something during work
hindsight memory retain my-project "The retry logic in api/client.rs has no backoff jitter, causing thundering herd under load" --context learnings

# Agent completes a partial fix
hindsight memory retain my-project "Fixed retry backoff in api/client.rs by adding exponential jitter. Still need to add circuit breaker logic." --context progress
```

**New sandbox session:**

```bash
# Agent recalls where the previous session left off
hindsight memory recall my-project "retry logic and backoff changes"

# Agent gets the full context and continues the work
```

### Pattern: Session Bookends

Adopt this pattern for every sandbox session:

1. **Session start**: `hindsight memory recall <bank-id> "<topic of current task>"`
2. **During work**: `hindsight memory retain <bank-id> "<learning>" --context learnings` (as discoveries happen)
3. **Session end**: `hindsight memory retain <bank-id> "<summary of progress and next steps>" --context progress`

## Network Policy

The sandbox must have a network policy allowing egress to the Hindsight API. Use the `generate-sandbox-policy` skill to create one, or add this block to your existing policy:

```yaml
network_policies:
  hindsight_memory:
    name: hindsight_memory
    endpoints:
      - host: api.hindsight.vectorize.io
        port: 443
        protocol: rest
        tls: terminate
        enforcement: enforce
        access: read-write
    binaries:
      - { path: /usr/local/bin/hindsight }
      - { path: /usr/bin/curl }
```

For self-hosted Hindsight instances on private networks, add `allowed_ips`:

```yaml
network_policies:
  hindsight_memory:
    name: hindsight_memory
    endpoints:
      - host: hindsight.internal.corp
        port: 8888
        protocol: rest
        enforcement: enforce
        access: read-write
        allowed_ips:
          - "10.0.5.0/24"
    binaries:
      - { path: /usr/local/bin/hindsight }
```

See the `generate-sandbox-policy` skill for full policy generation from these examples.

## Bank Management

Banks are isolated memory stores. Each project or team typically has its own bank.

```bash
# List available banks
hindsight bank list

# View bank statistics
hindsight bank stats <bank-id>

# View bank disposition (personality traits affecting reflect)
hindsight bank disposition <bank-id>
```

## Companion Skills

| Skill | When to Use |
|-------|-------------|
| `generate-sandbox-policy` | Generate or refine the network policy for Hindsight API access |
| `openshell-cli` | Manage providers, sandbox lifecycle, and policy attachment |
| `debug-inference` | If Hindsight uses a local inference endpoint for embeddings |

## CLI Quick Reference

| Command | Description |
|---------|-------------|
| `hindsight memory retain <bank> "text"` | Store a memory |
| `hindsight memory retain <bank> "text" --context <tag>` | Store with context tag |
| `hindsight memory retain-files <bank> <path>` | Retain from files |
| `hindsight memory recall <bank> "query"` | Search memories |
| `hindsight memory recall <bank> "query" --budget high` | Thorough search |
| `hindsight memory reflect <bank> "question"` | Synthesized answer |
| `hindsight bank list` | List banks |
| `hindsight bank stats <bank>` | Bank statistics |
| `hindsight configure` | Interactive CLI setup |
