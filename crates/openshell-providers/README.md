# openshell-providers

Imported provider profile parsing, validation, discovery, and environment
defaults.

The gateway persists provider records. The sandbox supervisor fetches resolved
provider environment from the gateway and injects credentials into agent child
processes. Profile declarations determine the behavior; profile IDs do not
select compiled provider plugins.

## Responsibilities

- Parse and round-trip the YAML, JSON, and protobuf profile schema.
- Discover credentials and non-secret config from declared environment keys.
- Apply bounded, literal non-secret environment defaults without overwriting
  existing values.
- Validate credential collisions and named platform adapter requirements.
- Avoid logging credential values.

## Non-Responsibilities

- Persisting provider records.
- Authorizing provider CRUD operations.
- Injecting credentials into sandbox child processes.
- Routing inference requests.

Those are owned by the gateway and sandbox supervisor.

## Provider Behavior Inventory

| Behavior | Declaration or disposition |
|---|---|
| GCP and Vertex project, region, and SDK aliases | `environment.config` |
| Metadata SDK variables and Goose provider default | `environment.fixed` |
| Credential discovery | `discovery.credentials` and credential `env_vars` |
| Vertex config discovery | `discovery.config_env_vars` |
| Workload resolution of non-secret values | Gateway key classification, independent of provider names |
| Platform service dependency | `required_platform_adapter`; GCP metadata is available for non-Windows sandbox runtimes |
| Vertex service account JSON credential | Removed from the example; configure gateway refresh material directly |
| ID-selected provider plugins | Removed |
| ID-selected CLI credential hints | Removed; setup guidance applies to the imported profile |
| `ProviderDiscoverySpec` and `discover_with_spec` | Removed; no supported caller |
| GCP token response helper | Retained in `openshell-core` for the supervisor metadata service |
| GCP project and region config-key catalog | Removed; profile data supplies these declarations |

Credential refresh strategies remain explicitly declared in credential metadata.
The supervisor provides the `gcp-metadata` adapter for Linux sandboxes; the
Windows/MXC runtime does not provide it.

## Security Notes

Provider data often contains API keys, bearer tokens, or local account
configuration. Discovery code should return structured values without printing
or tracing secrets. Callers that display provider data must redact sensitive
fields by default.
