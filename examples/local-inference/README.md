# Inference Routing Example

This example demonstrates NemoClaw's inference interception and routing.
A sandbox process sends inference traffic to `inference.local`, and
NemoClaw intercepts and reroutes it to the configured backend.

## How It Works

1. The sandbox process sends HTTPS traffic to `inference.local`.
2. The sandbox proxy intercepts that explicit inference endpoint locally.
3. The proxy TLS-terminates, parses the HTTP request, and detects known
   inference patterns (e.g., `POST /v1/chat/completions`).
4. Matching requests are forwarded to the configured backend via the sandbox's
   local router. Non-inference requests are denied.

## Files

| File | Description |
|---|---|
| `inference.py` | Python script that calls the OpenAI SDK through `https://inference.local/v1` |
| `sandbox-policy.yaml` | Minimal sandbox policy for the example |
| `routes.yaml` | Example YAML route file for standalone (no-cluster) mode |

## Quick Start

There are two ways to run inference routing: **with a cluster** (managed
routes, multi-sandbox) or **standalone** (single sandbox, routes from a file).

### Standalone (no cluster)

Run the sandbox binary directly with a route file — no NemoClaw cluster needed:

```bash
# 1. Edit routes.yaml to point at your local LLM (e.g. LM Studio on :1234)
#    See examples/inference/routes.yaml

# 2. Run the sandbox with --inference-routes
navigator-sandbox \
  --inference-routes examples/inference/routes.yaml \
  --policy-rules <your-policy.rego> \
  --policy-data examples/inference/sandbox-policy.yaml \
  -- python examples/inference/inference.py
```

The sandbox loads routes from the YAML file at startup and routes inference
requests locally — no gRPC server or cluster required.

### With a cluster

#### 1. Start a NemoClaw cluster

```bash
mise run cluster
nemoclaw status
```

#### 2. Configure cluster inference

First make sure a provider record exists for the backend you want to use:

```bash
nemoclaw provider list
```

Then configure the cluster-managed `inference.local` route:

```bash
# Example: use an existing provider record
nemoclaw cluster inference set \
  --provider openai-prod \
  --model gpt-4o-mini
```

Verify the active config:

```bash
nemoclaw cluster inference get
```

#### 3. Run the example inside a sandbox

```bash
nemoclaw sandbox create \
  --policy examples/inference/sandbox-policy.yaml \
  --keep \
  --name inference-demo \
  -- python examples/inference/inference.py
```

The script targets `https://inference.local/v1` directly. NemoClaw
intercepts that connection and routes it to whatever backend cluster
inference is configured to use.

Expected output:

```
model=<backend model name>
content=NAV_OK
```

#### 4. (Optional) Interactive session

```bash
nemoclaw sandbox connect inference-demo
# Inside the sandbox:
python examples/inference/inference.py
```

#### 5. Cleanup

```bash
nemoclaw sandbox delete inference-demo
```

## Customizing Routes

Edit `routes.yaml` to change which backend endpoint/model standalone mode uses.
In cluster mode, use `nemoclaw cluster inference set` instead.

## Supported Protocols

NemoClaw detects and routes the following inference API patterns:

| Pattern | Protocol | Kind |
|---|---|---|
| `POST /v1/chat/completions` | `openai_chat_completions` | Chat completion |
| `POST /v1/completions` | `openai_completions` | Text completion |
| `POST /v1/responses` | `openai_responses` | Responses API |
| `POST /v1/messages` | `anthropic_messages` | Anthropic messages |
