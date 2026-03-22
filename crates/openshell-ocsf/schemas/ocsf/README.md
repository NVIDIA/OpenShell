# Vendored OCSF Schemas

These schemas are vendored from the [OCSF Schema Server](https://schema.ocsf.io/)
for offline test validation.

## Version

- **OCSF v1.7.0** — fetched from `https://schema.ocsf.io/api/1.7.0/`

## Contents

### Classes (8)

- `network_activity` [4001]
- `http_activity` [4002]
- `ssh_activity` [4007]
- `process_activity` [1007]
- `detection_finding` [2004]
- `application_lifecycle` [6002]
- `device_config_state_change` [5019]
- `base_event` [0]

### Objects (17)

- `metadata`, `network_endpoint`, `network_proxy`, `process`, `actor`
- `device`, `container`, `product`, `firewall_rule`, `finding_info`
- `evidences`, `http_request`, `http_response`, `url`, `attack`
- `remediation`, `connection_info`

## Updating

To update to a new OCSF version:

```bash
VERSION=1.7.0

for class in network_activity http_activity ssh_activity process_activity \
             detection_finding application_lifecycle device_config_state_change base_event; do
  curl -s "https://schema.ocsf.io/api/${VERSION}/classes/${class}" \
    | python3 -m json.tool > "classes/${class}.json"
done

for object in metadata network_endpoint network_proxy process actor device \
              container product firewall_rule finding_info evidences \
              http_request http_response url attack remediation connection_info; do
  curl -s "https://schema.ocsf.io/api/${VERSION}/objects/${object}" \
    | python3 -m json.tool > "objects/${object}.json"
done

echo "${VERSION}" > VERSION
```

Then update `OCSF_VERSION` in `crates/openshell-ocsf/src/lib.rs` to match.
