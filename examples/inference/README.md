# Inference Routing Example

This example demonstrates NemoClaw's inference interception and routing.
A sandbox process makes standard API calls (OpenAI, Anthropic, etc.) and
NemoClaw transparently intercepts, enforces policy, and reroutes them to
a configured backend — without any code changes in the sandboxed application.

## How It Works

1. The sandbox proxy intercepts outgoing HTTPS connections.
2. OPA policy determines the action: if the binary has no explicit network
   policy but inference routing is configured, the connection is inspected.
3. The proxy TLS-terminates, parses the HTTP request, and detects known
   inference patterns (e.g., `POST /v1/chat/completions`).
4. Matching requests are forwarded directly to the policy-allowed inference
   backend via the sandbox's local router. Non-inference requests are denied.

## Files

| File | Description |
|---|---|
| `inference.py` | Python script that calls the OpenAI SDK — works unmodified inside a sandbox |
| `sandbox-policy.yaml` | Sandbox policy with inference routing enabled (route hint: `local`) |
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
nemoclaw cluster status
```

#### 2. Create an inference route

Point the route at any OpenAI-compatible endpoint (local or remote):

```bash
# Local model (e.g., LM Studio, Ollama, vLLM)
nemoclaw inference create \
  --routing-hint local \
  --base-url http://<HOST>:<PORT> \
  --model-id <MODEL_NAME>

# Remote provider (e.g., OpenAI, NVIDIA NIM)
nemoclaw inference create \
  --routing-hint local \
  --base-url https://api.openai.com \
  --api-key sk-... \
  --model-id gpt-4o-mini
```

If `--protocol` is omitted, NemoClaw auto-detects supported protocols by
probing the endpoint (sends minimal requests with `max_tokens: 1`).

Verify the route:

```bash
nemoclaw inference list
```

#### 3. Run the example inside a sandbox

```bash
nemoclaw sandbox create \
  --policy examples/inference/sandbox-policy.yaml \
  --keep \
  --name inference-demo \
  -- python examples/inference/inference.py
```

The script targets `https://api.openai.com` by default, but NemoClaw
intercepts the connection and routes it to whatever backend the `local`
route points at.

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
nemoclaw inference delete <route-name>
```

## Customizing the Policy

Edit `sandbox-policy.yaml` to control which routes are available:

```yaml
inference:
  allowed_routes:
    - local          # matches the --routing-hint used in step 2
    - production     # add more route hints as needed
```

The `allowed_routes` list determines which inference routes a sandbox can
use. Routes are matched by their `routing_hint` field.

## Supported Protocols

NemoClaw detects and routes the following inference API patterns:

| Pattern | Protocol | Kind |
|---|---|---|
| `POST /v1/chat/completions` | `openai_chat_completions` | Chat completion |
| `POST /v1/completions` | `openai_completions` | Text completion |
| `POST /v1/responses` | `openai_responses` | Responses API |
| `POST /v1/messages` | `anthropic_messages` | Anthropic messages |
