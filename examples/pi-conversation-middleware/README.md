# Pi conversation middleware prototype

This example contains the Pi hook adapter and policy for the standalone
`openshell-pi-conversation-middleware` reference server. See the crate README
for startup and gateway registration details.

The directory is also a complete local Docker build context. Its `Dockerfile`
installs Pi and copies `pi-extension.ts` plus `models.json` into the image.
OpenShell builds it automatically when creating the test sandbox:

```shell
openshell sandbox create \
  --from examples/pi-conversation-middleware/Dockerfile \
  --name pi-redaction-demo
```

The `models.json` file contains the literal `$NV_IAPI_API_KEY` environment
reference, not a credential. Attach an OpenShell provider when creating the
sandbox so Pi receives an opaque credential placeholder at runtime.

Load the extension from inside a Pi-capable sandbox:

```shell
pi --offline --no-tools --extension /path/to/pi-extension.ts
```

The extension calls only the stable supervisor URL at
`http://127.0.0.1:8193/v1/agent/conversation`; it does not know the operator
gRPC endpoint. `OPENSHELL_PI_CONVERSATION_URL` may override that prototype
default. The supervisor proxies each hook call through its registered
middleware client, stamps sandbox and provider identity, and returns the
replacement conversation plus opaque attestation.

For the smallest proof, select an `openai-completions` model, disable Pi tools,
and use the configured NVIDIA Inference API GPT-5.6 Sol model with text-only
messages. A prompt such as `describe a sandbox` is stored and sent as `describe
a REDACTED`. Any attempt to send the original body, alter the signed message
list, or omit the internal header is denied at egress.

This example is deliberately not a general Pi integration. Review the
limitations in the crate README before using it.
