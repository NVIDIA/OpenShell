# Provider-backed Inference Example

This example calls the NVIDIA API Catalog through its native OpenAI-compatible
endpoint. OpenShell supplies endpoint-bound credentials and network policy from
an explicitly imported provider profile; the Python client owns the endpoint,
model, request shape, timeout, and streaming behavior.

## Files

| File | Description |
|---|---|
| `nvidia-inference.yaml` | Example profile for the endpoint, credential, and allowed Python binaries |
| `inference.py` | Native endpoint streaming and non-streaming client |
| `sandbox-policy.yaml` | Minimal policy that lets Python install the OpenAI client from PyPI |

## Run the Example

Export the built-in profile as a starting point and compare it with the example
before import. A custom profile must use a new ID; built-in IDs are reserved.

```shell
openshell provider profile export nvidia -o yaml > /tmp/nvidia-profile.yaml
diff -u /tmp/nvidia-profile.yaml examples/local-inference/nvidia-inference.yaml
openshell provider profile lint -f examples/local-inference/nvidia-inference.yaml
openshell provider profile import -f examples/local-inference/nvidia-inference.yaml
```

Create the provider from the local `NVIDIA_API_KEY`, then attach it to the new
sandbox:

```shell
openshell provider create \
  --name nvidia-demo \
  --type nvidia-inference \
  --from-existing

openshell sandbox create \
  --name inference-demo \
  --provider nvidia-demo \
  --policy examples/local-inference/sandbox-policy.yaml \
  --upload examples/local-inference/inference.py \
  -- python3 /sandbox/inference.py
```

The profile contributes the NVIDIA endpoint to the effective network policy and
injects an opaque `NVIDIA_API_KEY` placeholder. The proxy substitutes the real
key only for requests that match the profile endpoint. Inspect the composed
policy with:

```shell
openshell policy get inference-demo --full
```

To change the endpoint or allowed client binaries, export the custom profile,
edit it, and submit its `resource_version` with `profile update`. The workload
still needs a native client configuration that matches the profile.

```shell
openshell provider profile export nvidia-inference -o yaml > nvidia-inference.yaml
# Edit nvidia-inference.yaml.
openshell provider profile lint -f nvidia-inference.yaml
openshell provider profile update nvidia-inference -f nvidia-inference.yaml
```

Delete the sandbox when finished:

```shell
openshell sandbox delete inference-demo
```
