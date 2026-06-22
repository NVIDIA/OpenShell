# Relay Inspection Demo

This directory holds a tiny shared inspector service for the Hermes + NeMo Relay + OpenShell demo.

Start the service:

```shell
python3 examples/relay-inspection-demo/inspector_service.py --host 127.0.0.1 --port 7777
```

Point Hermes at it:

```shell
export HERMES_NEMO_RELAY_INSPECTOR_URL=http://127.0.0.1:7777/inspect
```

Point OpenShell at it:

```shell
export OPENSHELL_REQUEST_INSPECTOR_URL=http://127.0.0.1:7777/inspect
```

Demo behavior:

- `llm_request`
  - redacts `alice@example.com` from semantic request payloads
- `tool_request`
  - denies inputs containing `DROP TABLE`
  - annotates `{"query": "books"}` with `relay_inspected: true`
- `http_request`
  - denies requests to `/blocked`
  - injects `x-inspected: true` on allowed requests that do not already carry it
