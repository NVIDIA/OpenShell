# Jupyter Sandbox

Launch one OpenShell sandbox, expose its Jupyter API server as a named service,
and submit Python code to a kernel through that service.

The example uses the OpenShell Python SDK for gateway health, sandbox creation,
readiness, command execution, and deletion. It uses the `openshell` CLI only for
service expose and delete operations that are not yet available in the SDK.

## Prerequisites

- A running local OpenShell gateway (`mise run gateway:docker` for development)
- The `openshell` CLI configured to use that gateway
- Docker to build the example image
- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/) to install the Python dependencies

The example supports a local gateway only. Remote service access requires
handling the gateway authentication boundary and is outside this example's
scope.

## Run the example

Install the Python dependencies, build the Jupyter image, and run the script:

```shell
cd examples/jupyter-sandbox
uv venv
source .venv/bin/activate
uv pip install openshell pyyaml websocket-client
docker build -t openshell-jupyter-sandbox:local .
python demo.py
```

The script:

1. Creates one sandbox from the configured image and policy through the Python
   SDK.
2. Starts a token-authenticated Jupyter Server on `127.0.0.1:8888` in the
   sandbox.
3. Exposes the server as an OpenShell service named `jupyter` and prints the
   service URL.
4. Creates a Python kernel with `POST /api/kernels` through the service.
5. Connects to `/api/kernels/{kernel_id}/channels` through the service and sends
   a Jupyter `execute_request` over WebSocket.
6. Prints the kernel output, then deletes the kernel, service, and sandbox.

The submitted code is:

```python
print(sum(i * i for i in range(10)))
```

The expected result is `285`.

## Submit code through the service

`JupyterSandbox` owns the sandbox, Jupyter server, exposed service, and cleanup
lifecycle. Call `execute()` inside its context to create a kernel and submit
code through the exposed service:

```python
with JupyterSandbox(
    client=client,
    name="jupyter-example",
    image="openshell-jupyter-sandbox:local",
    policy="policy.yaml",
) as sandbox:
    print(f"Jupyter service: {sandbox.service_url}")
    output = sandbox.execute("print('hello from Jupyter')")
    print(output)
```

Each sandbox gets a unique Jupyter token. The token travels to the sandbox over
standard input, is stored in a mode-restricted file, and is attached internally
to the REST and WebSocket requests. The example prints the service URL without
the token.

## Configure the sandbox

Edit the constants at the top of `demo.py` to select the image, policy, sandbox
name prefix, gateway, and code:

```python
IMAGE = "registry.example.com/jupyter-sandbox:latest"
POLICY = EXAMPLE_DIR / "my-policy.yaml"
NAME_PREFIX = "analysis"
CODE = 'print("hello from Jupyter")'
GATEWAY = None
```

`IMAGE` accepts an OCI image reference. The Python SDK does not currently build
a Dockerfile the way `openshell sandbox create --from` does, so build or publish
the image first. A custom image must provide `jupyter server`, a `python3`
kernel, and the non-root `sandbox` user and group selected by the policy.

`policy.yaml` allows the system paths Jupyter needs and writable access to
`/sandbox` and `/tmp`. Its empty `network_policies` map denies outbound network
access. Exposing the loopback Jupyter server through OpenShell is inbound and
does not require an egress rule.

## Proposed Python SDK APIs

The example still has deliberate seams because the SDK does not expose all CLI
functionality:

- Add `SandboxClient.expose_service()`, `get_service()`, `list_services()`, and
  `delete_service()`, returning a public `ServiceEndpoint` model. The example
  currently uses the `openshell service` CLI only for expose and delete.
- Add a public sandbox configuration builder that accepts `image` and a
  `SandboxPolicy`. The low-level client currently requires generated protobuf
  types from the private `openshell._proto` package.
- Add `load_sandbox_policy()` with the same canonical YAML validation and
  conversion as the CLI. This example only normalizes the
  `filesystem_policy` field needed by its policy before parsing the protobuf.
- Add an image-source helper with CLI parity for OCI references, Dockerfiles,
  and build directories. Until then, Python SDK callers must prepare the OCI
  image before creating a sandbox.

With those APIs, `JupyterSandbox` could remove its CLI subprocess adapter and
all imports from `openshell._proto`.
