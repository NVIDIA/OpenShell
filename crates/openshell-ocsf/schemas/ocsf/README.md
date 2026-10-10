# Vendored OCSF Schemas

These schemas are vendored from the [OCSF Schema Server](https://schema.ocsf.io/)
for offline validation.

## Versions

| Directory | Used for |
|---|---|
| `v1.8.0` | The native version (`OCSF_VERSION` in `src/lib.rs`). Schema tests validate every builder's events against it. |
| `v1.1.0`, `v1.3.0` | Downgrade targets. `src/format/downgrade_defs.rs` is generated from them, and downgrade tests validate against them. |
| `v1.7.0` | Previous native version; no test loads it. |

Each version directory holds the classes OpenShell emits (`network_activity`,
`http_activity`, `ssh_activity`, `process_activity`, `detection_finding`,
`application_lifecycle`, `device_config_state_change`, `api_activity`,
`base_event`) and the objects those events can contain. The validator loads an
object schema for every object attribute an event carries, so a missing file
fails the test with `Missing vendored schema: ...`; vendor that object.

With the `test-support` feature, the schemas are compiled into the binary
(`src/validation/embedded.rs`), so archived test binaries run on other machines
need no files from this directory.

## Updating

Fetch classes and objects for a version from the schema server API:

```bash
VERSION=1.8.0
DIR="v${VERSION}"
mkdir -p "${DIR}/classes" "${DIR}/objects"

for class in network_activity http_activity ssh_activity process_activity \
             detection_finding application_lifecycle device_config_state_change \
             api_activity base_event; do
  curl -sf "https://schema.ocsf.io/api/${VERSION}/classes/${class}" \
    | python3 -m json.tool > "${DIR}/classes/${class}.json"
done

for object in metadata network_endpoint network_proxy network_connection_info \
              process actor device os container product firewall_rule \
              finding_info evidences http_request http_response url attack \
              remediation api; do
  curl -sf "https://schema.ocsf.io/api/${VERSION}/objects/${object}" \
    | python3 -m json.tool > "${DIR}/objects/${object}.json"
done

echo "${VERSION}" > "${DIR}/VERSION"
```

Some objects exist only in later versions (for example `ai_model`); fetch them
for the versions that define them.

After adding or removing any schema file, regenerate the embedded table, and
after changing any `v1.1.0` or `v1.3.0` file, regenerate the downgrade
definitions:

```bash
UPDATE_OCSF_EMBEDDED_SCHEMAS=1 cargo test -p openshell-ocsf embedded_schemas
UPDATE_OCSF_DOWNGRADE_DEFS=1 cargo test -p openshell-ocsf downgrade_definitions
```

## Changing the native version

When moving `OCSF_VERSION` to a new release:

1. Vendor the new version directory as above and update `OCSF_VERSION` in
   `src/lib.rs`.
2. Run `cargo test -p openshell-ocsf`. `every_builder_emits_schema_conformant_events`
   reports attributes that are newly required, renamed, or undefined.
3. Check the downgrade: `every_sample_event_claims_a_version_it_conforms_to`
   confirms each older target still validates. Attributes added in the new
   version move under `unmapped.downgraded_attributes` automatically.
4. Update `docs/observability/ocsf-json-export.mdx` and the version strings in
   the docs and Helm chart.
5. Validate real output against the official server (below).

## Validating against the official OCSF server

The vendored-schema validator checks presence, nesting, undefined attributes,
and profiles. It does not check value types or enum ranges. To check those,
run the official [OCSF server](https://github.com/ocsf/ocsf-server) locally,
one instance per version:

```bash
git clone --depth 1 https://github.com/ocsf/ocsf-server.git
podman build -t ocsf-server ocsf-server

# The compiler requires Python 3.14 or later.
uv venv --python 3.14 .venv && uv pip install --python .venv/bin/python ocsf-schema-compiler
mkdir -p compiled
for v in v1.1.0 v1.3.0 v1.8.0; do
  git clone --depth 1 --branch "$v" https://github.com/ocsf/ocsf-schema.git "ocsf-schema-$v"
  .venv/bin/ocsf-schema-compiler "ocsf-schema-$v" -b > "compiled/ocsf-schema-$v-browser.json"
done

podman run -d --name ocsf-1.8.0 -v "$PWD/compiled:/app/schemas:ro" \
  -e SCHEMA_FILE=/app/schemas/ocsf-schema-v1.8.0-browser.json \
  -p 127.0.0.1:18150:8080 ocsf-server
```

Then `POST` each JSONL record to `http://127.0.0.1:18150/api/validate`; an empty
JSON object means the record is valid. Run instances for `v1.1.0` and `v1.3.0`
on other ports to check downgraded records, choosing the instance by each
record's `metadata.version`.
