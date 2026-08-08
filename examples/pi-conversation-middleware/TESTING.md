# Pi conversation middleware manual test

This guide exercises the narrow Pi conversation middleware prototype end to
end:

1. Pi sends its hook conversation to the stable supervisor HTTP bridge.
2. The supervisor proxies the hook request to the operator gRPC middleware.
3. The middleware replaces `sandbox` with `REDACTED` and signs the sanitized
   conversation.
4. The Pi extension applies the replacement and attaches the attestation to the
   OpenAI Chat Completions request.
5. Fail-closed HTTP egress middleware verifies the exact signed message array,
   strips the internal attestation header, and forwards the request.

## Important constraints

- `openshell sandbox create --from <Dockerfile>` builds the image
  automatically through the local Docker daemon. The complete build context is
  checked in under `examples/pi-conversation-middleware`; do not run a separate
  `docker build` or generate temporary build files.
- This prototype supports OpenAI Chat Completions only. Pi's Codex subscription
  provider uses the Codex Responses API and is intentionally unsupported.
- Use an NVIDIA Inference API key for this test. Do not copy credentials into
  the image or sandbox.
- Use text-only input, a non-reasoning model, and no Pi tools.
- Start Pi with `--offline` so it does not attempt unrelated startup downloads
  from `pi.dev` or GitHub. This does not disable model inference.
- The local Docker gateway must use the combined supervisor topology.

## Prerequisites

- Docker Desktop or another reachable Docker daemon
- The repository development dependencies installed
- An NVIDIA Inference API key that can be supplied to an OpenShell provider

Run all host commands from the repository root:

```shell
docker info
```

## 1. Inspect the checked-in Docker build context

The example directory already contains everything needed for the local image
build:

```shell
ls examples/pi-conversation-middleware
```

The relevant files are:

- `Dockerfile`: installs Pi, declares a non-root OCI user, and copies the Pi
  configuration and extension into the image.
- `models.json`: configures GPT-5.6 Sol through the NVIDIA Inference API's
  OpenAI Chat Completions endpoint.
- `pi-extension.ts`: forwards Pi hook data to the stable supervisor bridge and
  applies the signed mutation.
- `policy.yaml`: attaches fail-closed middleware to
  `inference-api.nvidia.com` and grants read-only filesystem access to the
  extension under `/opt/pi-conversation`.

The string `$NV_IAPI_API_KEY` in `models.json` is a literal
environment-variable reference, not a credential value. The build context and
resulting image contain no API key. At runtime, Pi resolves that reference from
the opaque environment placeholder populated by the attached OpenShell
provider.

## 2. Start the operator gRPC middleware

In terminal 1:

```shell
RUST_LOG=info cargo run \
  -p openshell-pi-conversation-middleware \
  -- \
  --listen 0.0.0.0:50061
```

Leave this process running.

## 3. Prepare and start the local Docker gateway

The development task builds the gateway and Linux sandbox supervisor and
generates the Docker-driver configuration. It currently rewrites its generated
configuration on every invocation, so run it once, stop it, add the prototype
registration, and then launch the prepared gateway binary directly.

In terminal 2:

```shell
mise run gateway:docker
```

Wait for `Starting standalone Docker gateway`, then press Ctrl-C. Register the
operator middleware in the generated configuration. The registration endpoint
must be reachable both by the gateway on macOS and by Docker sandboxes. On this
Mac, use the active Wi-Fi IPv4 address:

```shell
MIDDLEWARE_HOST_IP="$(ipconfig getifaddr en0)"
test -n "$MIDDLEWARE_HOST_IP" || {
  echo "Could not find the host IPv4 address on en0" >&2
  return 1
}
nc -vz "$MIDDLEWARE_HOST_IP" 50061

cat >> .cache/gateway-docker/gateway.toml <<EOF

[[openshell.supervisor.middleware]]
name = "pi-conversation-prototype"
grpc_endpoint = "http://${MIDDLEWARE_HOST_IP}:50061"
max_body_bytes = 262144
timeout = "5s"
EOF
```

Start the prepared gateway without regenerating its configuration:

```shell
target/debug/openshell-gateway \
  --config "$PWD/.cache/gateway-docker/gateway.toml" \
  --port 18080 \
  --log-level info \
  --drivers docker \
  --disable-tls \
  --db-url "sqlite:$PWD/.cache/gateway-docker/gateway.db?mode=rwc"
```

Leave this process running. Do not rerun `mise run gateway:docker` after
appending the registration because it will overwrite `gateway.toml`.

## 4. Store the NVIDIA Inference API credential in an OpenShell provider

In terminal 3, read the NVIDIA Inference API key into the host environment
without placing its value in shell history:

```shell
read -s NV_IAPI_API_KEY
export NV_IAPI_API_KEY
test -n "$NV_IAPI_API_KEY" && echo "NVIDIA Inference API key is available"
```

Create an OpenShell provider. The bare `--credential NV_IAPI_API_KEY` argument
instructs the CLI to read the value from the host environment; it does not put
the value in argv or command history:

```shell
./scripts/bin/openshell \
  --gateway docker-dev \
  provider create \
  --name pi-nvidia-inference-prototype \
  --type generic \
  --credential NV_IAPI_API_KEY \
  --config base_url=https://inference-api.nvidia.com/v1
```

If `pi-nvidia-inference-prototype` already exists from an earlier run, reuse it
rather than creating it again. Once provider creation succeeds, remove the
temporary host-shell copy:

```shell
unset NV_IAPI_API_KEY
```

The gateway stores the provider credential. When the provider is attached to a
sandbox, OpenShell injects an opaque placeholder as `NV_IAPI_API_KEY` and
resolves that placeholder at the egress proxy. The real key is never copied
into the Docker build context, Docker image, or sandbox environment.

## 5. Build the image and create the sandbox

This single command sends the Dockerfile build context to the local Docker
gateway, builds the image, creates the sandbox, attaches the credential
provider, and starts the supervisor:

```shell
./scripts/bin/openshell \
  --gateway docker-dev \
  sandbox create \
  --name pi-redaction-demo \
  --from examples/pi-conversation-middleware/Dockerfile \
  --provider pi-nvidia-inference-prototype \
  --policy examples/pi-conversation-middleware/policy.yaml
```

The filesystem policy is static. If you created `pi-redaction-demo` with an
earlier version of this policy, delete and recreate that sandbox before
testing; `openshell policy set` cannot add the extension path to a running
sandbox's Landlock rules.

The supervisor discovers the Pi bridge from the registered service's agent-hook
bindings and the selected middleware policy. It takes the provider host from
the policy's single exact `endpoints.include` entry. The extension defaults to
this stable loopback URL, so it also works in SSH sessions that do not inherit
the entrypoint environment:

```text
http://127.0.0.1:8193/v1/agent/conversation
```

`OPENSHELL_PI_CONVERSATION_URL` is an optional prototype override, not a
required user setting. Do not pass any `OPENSHELL_*` values through
`openshell sandbox create --env`; the CLI reserves that namespace for
supervisor-owned configuration.

## 6. Connect over SSH and start Pi

```shell
./scripts/bin/openshell \
  --gateway docker-dev \
  sandbox connect pi-redaction-demo
```

Inside the sandbox, verify the credential placeholder without printing it:

```shell
test -n "$NV_IAPI_API_KEY" && echo "NVIDIA Inference API credential placeholder is available"
```

Start Pi with tools disabled and the prototype extension loaded:

```shell
pi \
  --offline \
  --no-tools \
  --extension /opt/pi-conversation/pi-extension.ts \
  --provider nvidia-inference-api \
  --model azure/openai/gpt-5.6-sol
```

Send this prompt:

```text
Reply with exactly the final word in this sentence: sandbox
```

The model-visible prompt must be:

```text
Reply with exactly the final word in this sentence: REDACTED
```

The expected assistant response is therefore:

```text
REDACTED
```

Terminal 1 should also print a pretty-JSON `Pi conversation mutation` event
containing the complete `original` and `replacement` conversations.

In another host terminal, confirm that egress passed the mandatory attestation
check:

```shell
./scripts/bin/openshell \
  --gateway docker-dev \
  logs pi-redaction-demo \
  --since 5m \
  --source sandbox
```

The request should have an allowed middleware event containing
`engine:middleware`, `failed:false`, and `transformed:true`. A
`missing_attestation` denial indicates that Pi used an old or unloaded
extension.

After exiting Pi, inspect its persisted session data:

```shell
grep -R -n 'REDACTED' /workspace/.pi/agent/sessions
```

## 7. Optional fail-closed check

From the sandbox shell, send a direct Chat Completions request using the
allowed Node binary but without an attestation:

```shell
node <<'NODE'
fetch("https://inference-api.nvidia.com/v1/chat/completions", {
  method: "POST",
  headers: {
    "authorization": `Bearer ${process.env.NV_IAPI_API_KEY}`,
    "content-type": "application/json"
  },
  body: JSON.stringify({
    model: "azure/openai/gpt-5.6-sol",
    messages: [{ role: "user", content: "sandbox" }]
  })
}).then(async response => {
  console.log("status:", response.status);
  console.log(await response.text());
});
NODE
```

The request must receive a non-2xx denial because it lacks the internal
`x-openshell-agent-attestation` header. The gateway or sandbox logs should
identify `missing_attestation` as the middleware reason.

## 8. Cleanup

Exit the SSH session and remove the sandbox:

```shell
./scripts/bin/openshell \
  --gateway docker-dev \
  sandbox delete pi-redaction-demo
```

Stop the gateway and operator middleware with Ctrl-C in their terminals.

## Troubleshooting

### The gateway task overwrote the middleware registration

Run `mise run gateway:docker`, stop it after startup, append the registration
again, and restart `target/debug/openshell-gateway` directly as shown above.

### Pi rejects the selected model

Confirm Pi is using provider `nvidia-inference-api`, API
`openai-completions`, and a model with `reasoning: false`. Pi's built-in
`openai` and `openai-codex` providers use Responses request shapes and will be
rejected by this prototype.

### Pi tries to download fd or ripgrep

Use the documented `--offline` flag. Those downloads support optional Pi
features and are unnecessary because this prototype starts Pi with tools
disabled. The sandbox policy intentionally does not allow `pi.dev` or GitHub.

### The extension reports that the bridge URL is not set

The current extension has the stable loopback bridge URL built in. This error
means the sandbox image contains an older `pi-extension.ts`. Delete and
recreate the sandbox with the checked-in Dockerfile so OpenShell rebuilds the
image from the current example context.

### Pi cannot read `/opt/pi-conversation/pi-extension.ts`

The extension directory must appear in `filesystem_policy.read_only` when the
sandbox starts. Filesystem policy is static, so delete and recreate any sandbox
created with an older `policy.yaml`; a policy hot reload cannot repair this
Landlock denial.

### `--env OPENSHELL_PI_CONVERSATION_*` is rejected

Remove those arguments. `OPENSHELL_*` is reserved, and the supervisor now
discovers the bridge middleware from its registered agent-hook bindings plus
the selected middleware policy.

### NVIDIA Inference API key is unavailable

Confirm `NV_IAPI_API_KEY` is present in the host shell when creating the
`generic` OpenShell provider. Do not pass the key through `--env` or copy it
into the Docker build context.

### The middleware cannot be reached

Confirm terminal 1 is listening on `0.0.0.0:50061`, the gateway registration
uses the Mac's active LAN IPv4 address, and `nc -vz "$MIDDLEWARE_HOST_IP" 50061`
succeeds from macOS. `host.openshell.internal` is injected into Docker
sandboxes, but it does not resolve in the host-side gateway process on macOS.
