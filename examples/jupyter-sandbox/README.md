# Jupyter Sandbox

Run a published Jupyter image in Ryno, expose its server locally, and
execute a local notebook on the sandboxed kernel.

Run these commands from `examples/jupyter-sandbox`. You need a local Ryno
gateway, the `ryno` CLI, Cargo, and OpenSSL on the host.

## 1. Install the notebook CLI

Install the [Jupyter community notebook CLI](https://github.com/jupyter-ai-contrib/nb-cli):

```shell
cargo install nb-cli --version 0.0.10 --locked
```

Ryno pulls the published `quay.io/jupyter/base-notebook:2026-09-29` image
when it creates the sandbox. The image includes Jupyter Server and a Python
kernel, so no container build is needed.

## 2. Launch the service

```shell
JUPYTER_TOKEN="$(openssl rand -hex 32)"
ryno sandbox create \
  --name jupyter-demo \
  --from quay.io/jupyter/base-notebook:2026-09-29 \
  --policy policy.yaml \
  --expose 8888 \
  --detach --no-tty \
  -- jupyter server \
    --ServerApp.ip=127.0.0.1 \
    --ServerApp.port=8888 \
    --ServerApp.port_retries=0 \
    --ServerApp.open_browser=False \
    --ServerApp.root_dir=/home/jovyan \
    --ServerApp.terminals_enabled=False \
    --ServerApp.allow_remote_access=True \
    --IdentityProvider.token="$JUPYTER_TOKEN"
```

The CLI prints the service URL after the sandbox is ready. Jupyter starts as
the sandbox's main process and listens on its loopback port. Keep the token in
this shell for step 3.

## 3. Execute the notebook on the remote kernel

Use the service URL printed in step 2 as the `--gateway` value:

```shell
nb execute demo.ipynb \
  --gateway 'http://default--jupyter-demo.ryno.localhost:<gateway-port>/' \
  --gateway-token "$JUPYTER_TOKEN"
```

The command writes `285` into `demo.ipynb` on your computer. Its code
runs in a Jupyter kernel inside the sandbox. The `nb` CLI accepts the service
URL as a flag and authenticates its REST and WebSocket connections.

When finished, delete the sandbox and its service:

```shell
ryno sandbox delete jupyter-demo
```
