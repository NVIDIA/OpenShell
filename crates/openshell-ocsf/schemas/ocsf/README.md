# Vendored OCSF Schemas

These schemas are vendored from the [OCSF Schema Server](https://schema.ocsf.io/)
for offline test validation.

## Version

- **OCSF v1.8.0**, fetched from `https://schema.ocsf.io/api/1.8.0/`

## Contents

### Classes (10)

- `network_activity` [4001]
- `http_activity` [4002]
- `ssh_activity` [4007]
- `process_activity` [1007]
- `detection_finding` [2004]
- `application_lifecycle` [6002]
- `device_config_state_change` [5019]
- `api_activity` [6003]
- `authentication` [3002]
- `base_event` [0]

### Objects (26)

- `metadata`, `network_endpoint`, `network_proxy`, `process`, `actor`
- `device`, `container`, `product`, `firewall_rule`, `finding_info`
- `evidences`, `http_request`, `http_response`, `url`, `attack`
- `remediation`, `connection_info`, `network_connection_info`, `ai_model`,
  `api`, `user`, `service`, `os`, `resource_details`, `tactic`, `technique`

### Profiles (1)

- `ai_operation`

The validator loads an object schema for every object attribute an event
carries, so a missing file fails the test with `Missing vendored schema: ...`;
vendor that object.

With the `test-support` feature, the schemas are compiled into the binary
(`src/validation/embedded.rs`), so archived test binaries run on other machines
need no files from this directory.

## Updating

To update to a new OCSF version:

```bash
VERSION=1.8.0
DIR="v${VERSION}"
mkdir -p "${DIR}/classes" "${DIR}/objects"

for class in network_activity http_activity ssh_activity process_activity \
             detection_finding application_lifecycle device_config_state_change \
             api_activity authentication base_event; do
  curl -sf "https://schema.ocsf.io/api/${VERSION}/classes/${class}" \
    | python3 -m json.tool > "${DIR}/classes/${class}.json"
done

for object in metadata network_endpoint network_proxy process actor device \
              container product firewall_rule finding_info evidences \
              http_request http_response url attack remediation connection_info \
              network_connection_info ai_model api user service os resource_details tactic technique; do
  curl -sf "https://schema.ocsf.io/api/${VERSION}/objects/${object}" \
    | python3 -m json.tool > "${DIR}/objects/${object}.json"
done

echo "${VERSION}" > "${DIR}/VERSION"
```

After adding or removing any schema file, regenerate the embedded table:

```bash
UPDATE_OCSF_EMBEDDED_SCHEMAS=1 cargo test -p openshell-ocsf embedded_schemas
```

Then update `OCSF_VERSION` in `crates/openshell-ocsf/src/lib.rs` to match, run
`cargo test -p openshell-ocsf` (`every_builder_emits_schema_conformant_events`
reports attributes that are newly required, renamed, or undefined), and update
the version strings in `docs/observability/ocsf-json-export.mdx`.

## Validating against the official OCSF server

The vendored-schema validator checks presence, nesting, undefined attributes,
and profiles. It does not check value types or enum ranges. To check those,
run the official [OCSF server](https://github.com/ocsf/ocsf-server) locally:

```bash
git clone --depth 1 https://github.com/ocsf/ocsf-server.git
podman build -t ocsf-server ocsf-server

# The compiler requires Python 3.14 or later.
uv venv --python 3.14 .venv && uv pip install --python .venv/bin/python ocsf-schema-compiler
mkdir -p compiled
git clone --depth 1 --branch v1.8.0 https://github.com/ocsf/ocsf-schema.git ocsf-schema-v1.8.0
.venv/bin/ocsf-schema-compiler ocsf-schema-v1.8.0 -b > compiled/ocsf-schema-v1.8.0-browser.json

podman run -d --name ocsf-1.8.0 -v "$PWD/compiled:/app/schemas:ro" \
  -e SCHEMA_FILE=/app/schemas/ocsf-schema-v1.8.0-browser.json \
  -p 127.0.0.1:18150:8080 ocsf-server
```

Then `POST` each JSONL record to `http://127.0.0.1:18150/api/v2/validate`. A
record is valid when the response has `"error_count": 0`; the response lists
each problem under `errors`. Use the v2 endpoint: the older `/api/validate`
does not report constraint failures such as `at_least_one`, so a record missing
both endpoints can look valid.

To check against the hosted server instead, use
`https://schema.ocsf.io/api/1.8.0/v2/validate`. Keep the version in the path;
the unversioned `/api/v2/validate` validates against the latest OCSF version.
