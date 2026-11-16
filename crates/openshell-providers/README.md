# openshell-providers

Provider discovery and normalization for credentials that sandboxes need at
runtime.

The gateway persists provider records. The sandbox supervisor fetches resolved
provider environment from the gateway and injects credentials into agent child
processes. This crate keeps provider-specific discovery and normalization logic
out of the CLI and gateway control flow.

## Responsibilities

- Discover local credentials from environment variables and known config files.
- Normalize discovered data into provider records.
- Keep provider-specific parsing rules in provider modules.
- Use the shared authored-YAML compatibility boundary for profile imports and
  exports: reject duplicate keys and null objects without coercion, retain
  optional nulls, and preserve string types for YAML 1.1 readers.
- Avoid logging credential values.

## Non-Responsibilities

- Persisting provider records.
- Authorizing provider CRUD operations.
- Injecting credentials into sandbox child processes.
- Routing inference requests.

Those are owned by the gateway, sandbox supervisor, and router.

## Security Notes

Provider data often contains API keys, bearer tokens, or local account
configuration. Discovery code should return structured values without printing
or tracing secrets. Callers that display provider data must redact sensitive
fields by default.
