# Vendored OCSF Schemas

These schemas are vendored from the [OCSF Schema Server](https://schema.ocsf.io/)
for offline test validation.

## Version

- OCSF v1.8.0, fetched from `https://schema.ocsf.io/api/1.8.0/`

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
- `remediation`, `connection_info`, `ai_model`, `api`, `user`, `service`, `os`
- `resource_details`, `trace`, `span`, `key_value_object`

### Profiles (2)

- `ai_operation`, `trace`

All ten classes include the `trace` attribute from the OCSF 1.8.0 Trace
profile, with `profiles: ["trace"]`. HTTP and API Activity include it by default;
the other class schemas add it for offline validation of automatically
correlated events. The attribute is recommended, not required. The `trace`,
`span`, `service`, and `key_value_object` schemas are vendored unchanged.
Events contain only `trace.uid`.

## Updating

To update to a new OCSF version:

```shell
VERSION=1.8.0

for class in network_activity http_activity ssh_activity process_activity \
             detection_finding application_lifecycle device_config_state_change \
             api_activity authentication base_event; do
  curl -s "https://schema.ocsf.io/api/${VERSION}/classes/${class}" \
    | python3 -m json.tool > "classes/${class}.json"
done

for object in metadata network_endpoint network_proxy process actor device \
              container product firewall_rule finding_info evidences \
              http_request http_response url attack remediation connection_info \
              ai_model api user service os resource_details trace span key_value_object; do
  curl -s "https://schema.ocsf.io/api/${VERSION}/objects/${object}" \
    | python3 -m json.tool > "objects/${object}.json"
done

for profile in ai_operation trace; do
  curl -s "https://schema.ocsf.io/api/${VERSION}/profiles/${profile}" \
    | python3 -m json.tool > "profiles/${profile}.json"
done

# Compose Trace on every class after refreshing the official schemas.
uv run python - <<'PY'
import copy
import json
from pathlib import Path

attribute = json.loads(Path("profiles/trace.json").read_text())["attributes"]["trace"]
attribute["profiles"] = ["trace"]
for path in Path("classes").glob("*.json"):
    schema = json.loads(path.read_text())
    schema["attributes"]["trace"] = copy.deepcopy(attribute)
    if "trace" not in schema.setdefault("profiles", []):
        schema["profiles"].append("trace")
    path.write_text(json.dumps(schema, indent=4) + "\n")
PY

echo "${VERSION}" > VERSION
```

Then update `OCSF_VERSION` in `crates/openshell-ocsf/src/lib.rs` to match.
