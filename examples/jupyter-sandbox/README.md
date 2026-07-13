# Jupyter Sandbox Fleet

Launch several OpenShell sandboxes, expose each Jupyter API server as a named
OpenShell service, and submit Python code to one member through Jupyter's REST
and kernel WebSocket APIs.

The example keeps the fleet abstraction separate from the sandbox type:
`Fleet[T]` can compose any context-managed resource, while `JupyterSandbox`
owns one sandbox's OpenShell, Jupyter, service, and cleanup lifecycle. It uses
the OpenShell Python SDK for gateway health, sandbox creation, readiness,
command execution, and deletion.

## Prerequisites

- A running local OpenShell gateway (`mise run gateway:docker` for development)
- The `openshell` CLI configured to use that gateway for the temporary service
  expose/delete fallback
- Docker to build the example image
- Python 3.11 or later with `openshell`, `pyyaml`, and `websocket-client`
- [uv](https://docs.astral.sh/uv/) to install the Python dependencies

The example intentionally supports a local gateway only. Remote service access
requires handling the gateway's authentication boundary and is outside this
example's scope.

## Launch three sandboxes

Install the Python dependencies, build the Jupyter-ready image once, and run
the script:

```shell
cd examples/jupyter-sandbox
uv venv
source .venv/bin/activate
uv pip install openshell pyyaml websocket-client
docker build -t openshell-jupyter-sandbox:local .
python demo.py
```

The demo performs these operations:

1. Verifies the selected gateway through `SandboxClient.health()`.
2. Creates three sandboxes from the configured image and policy through the
   Python SDK.
3. Starts Jupyter Server on `127.0.0.1:8888` in each sandbox.
4. Exposes every server as an OpenShell service named `jupyter`.
5. Creates a kernel in the first sandbox and executes this code over the
   Jupyter API:

   ```python
   print(sum(i * i for i in range(10)))
   ```

6. Deletes every service and sandbox when the context exits, including after
   an exception. Sandbox deletion uses the Python SDK.

The expected result is `285`.

## Configure the fleet

Edit the configuration constants at the top of `demo.py` to select the sandbox
image, fleet size, policy, names, gateway, and work:

```python
IMAGE = "registry.example.com/jupyter-sandbox:latest"
SANDBOX_COUNT = 5
POLICY = EXAMPLE_DIR / "my-policy.yaml"
NAME_PREFIX = "analysis"
CODE = 'print("hello from Jupyter")'
GATEWAY = None
```

`IMAGE` accepts an OCI image reference. The Python SDK does not currently
build a Dockerfile the way `openshell sandbox create --from` does, so build or
publish the image first. A custom image must provide `jupyter server` and a
`python3` kernel. It must also contain a non-root `sandbox` user and group
because the included policy selects that process identity. The included
Dockerfile uses `python:3.13-slim`, creates that identity, and installs pinned
Jupyter dependencies.

`policy.yaml` allows the system paths Jupyter needs and writable access to
`/sandbox` and `/tmp`. Its empty `network_policies` map denies outbound network
access. Exposing the loopback Jupyter server through OpenShell is inbound and
does not require an egress rule. Replace the policy when notebook work needs
explicit outbound destinations.

## Reuse the abstraction

The core composition is deliberately small:

```python
with Fleet(
    count=3,
    factory=lambda index: JupyterSandbox(
        client=client,
        name=f"jupyter-{run_id}-{index + 1}",
        image=image,
        policy=policy,
    ),
) as fleet:
    print(fleet[0].execute("print(sum(i * i for i in range(10)))"))
```

Each sandbox gets a unique Jupyter token. The token travels to the sandbox over
standard input, is stored in a mode-restricted file, and is attached internally
to Jupyter API requests. The example never prints token-bearing URLs. OpenShell
service URLs shown by the demo are safe to display but still require the
process-local token for Jupyter API access.

## Proposed Python SDK APIs

This example still has deliberate seams because the SDK does not expose
all of the CLI's functionality:

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
