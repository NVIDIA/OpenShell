# Inference Routing Example

This example demonstrates OpenShell's inference interception and routing.
A sandbox process sends inference traffic to `inference.local`, and
OpenShell intercepts and reroutes it to the configured backend.

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
| `inference.py` | Python script that tests streaming and non-streaming inference through `inference.local` |
| `sandbox-policy.yaml` | Minimal sandbox policy (no network access except `inference.local`) |
| `routes.yaml` | Example YAML route file for standalone (no-cluster) mode |

## Quick Start (NVIDIA)

Requires a running OpenShell gateway and `NVIDIA_API_KEY` set in your shell.

```bash
# 1. Create a provider using your NVIDIA credentials
openshell provider create --name nvidia --type nvidia --credential NVIDIA_API_KEY

# 2. Configure inference routing
openshell inference set --provider nvidia --model meta/llama-3.1-8b-instruct

# 3. Run the test script in a sandbox
openshell sandbox create \
  --policy examples/local-inference/sandbox-policy.yaml \
  --upload examples/local-inference/inference.py \
  -- python3 /sandbox/inference.py
```

Expected output (with the streaming buffering bug present):

```
============================================================
NON-STREAMING REQUEST
============================================================
  model   = meta/llama-3.1-8b-instruct
  content = Glowing screens abide
            Whirring circuits, silent mind
            Tech's gentle grasp
  total   = 0.96s

============================================================
STREAMING REQUEST
============================================================
  TTFB    = 0.54s
  model   = meta/llama-3.1-8b-instruct
  content = Glowing screens abide
            Code and circuits whisper
            Silent digital
  total   = 0.54s

  ** BUG: TTFB is 99% of total time — response was buffered, not streamed **
```

When streaming works correctly, TTFB should be sub-second while total time
stays the same (tokens arrive incrementally).

## Standalone (no cluster)

Run the sandbox binary directly with a route file — no OpenShell cluster needed:

```bash
# 1. Edit routes.yaml to point at your local LLM (e.g. LM Studio on :1234)

# 2. Run the sandbox with --inference-routes
openshell-sandbox \
  --inference-routes examples/local-inference/routes.yaml \
  --policy-rules <your-policy.rego> \
  --policy-data examples/local-inference/sandbox-policy.yaml \
  -- python examples/local-inference/inference.py
```

The sandbox loads routes from the YAML file at startup and routes inference
requests locally — no gRPC server or cluster required.

### With a cluster

#### 1. Start a OpenShell cluster

```bash
mise run cluster
openshell status
```

#### 2. Configure cluster inference

First make sure a provider record exists for the backend you want to use:

```bash
openshell provider list
```

Then configure the cluster-managed `inference.local` route:

```bash
# Example: use an existing provider record
openshell cluster inference set \
  --provider openai-prod \
  --model nvidia/nemotron-3-nano-30b-a3b
```

Verify the active config:

```bash
openshell cluster inference get
```

#### 3. Run the example inside a sandbox

```bash
openshell sandbox create \
  --policy examples/inference/sandbox-policy.yaml \
  --name inference-demo \
  -- python examples/inference/inference.py
```

The script targets `https://inference.local/v1` directly. OpenShell
intercepts that connection and routes it to whatever backend cluster
inference is configured to use.

Expected output:

```
model=<backend model name>
content=NAV_OK
```

#### 4. (Optional) Interactive session

```bash
openshell sandbox connect inference-demo
# Inside the sandbox:
python examples/inference/inference.py
```

#### 5. Cleanup

```bash
openshell sandbox delete inference-demo
```

## Customizing Routes

Edit `routes.yaml` to change which backend endpoint/model standalone mode uses.
In cluster mode, use `openshell cluster inference set` instead.

## Supported Protocols

| Pattern | Protocol | Kind |
|---|---|---|
| `POST /v1/chat/completions` | `openai_chat_completions` | Chat completion |
| `POST /v1/completions` | `openai_completions` | Text completion |
| `POST /v1/responses` | `openai_responses` | Responses API |
| `POST /v1/messages` | `anthropic_messages` | Anthropic messages |
