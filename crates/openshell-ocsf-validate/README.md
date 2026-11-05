# openshell-ocsf-validate

Validates OCSF events against JSON Schemas exported by the OCSF schema server.

OCSF validity depends on the profiles an event declares in `metadata.profiles`, and an exported JSON Schema covers one fixed set of profiles. `schemas/v<version>/` therefore holds one schema per event class and profile combination, named `<class>@<profile>+<profile>.json` with profiles sorted. `validate_event` picks the schema from the event's `metadata.version`, `class_uid`, and declared profiles, and fails when none is vendored.

The schemas check required attributes, `at_least_one` constraints, undefined attributes, types, and enum values, including the class and category identifiers. The schemas type `type_uid` only as an integer, so `validate_event` also checks that it equals `class_uid * 100 + activity_id`. Supervisor sandbox identity is validated under `device.container` with the `container` profile; undefined top-level `container` objects are rejected.

## Updating

When a test validates an event whose version, class, and profile combination has no vendored schema, the error prints the command that vendors it. Run it from the repository root and commit the new file:

```shell
crates/openshell-ocsf-validate/schemas/update.sh crates/openshell-ocsf-validate/schemas/v1.8.0/network_activity@host+network_proxy+security_control.json
```

Without arguments, `schemas/update.sh` refetches every vendored schema. The schema server takes up to a few minutes per export. The build embeds every file under `schemas/v*/`, so tests need no source checkout at run time.

### Trace profile

The OCSF 1.8.0 schema server exports the Trace profile for HTTP Activity and API Activity. For the other eight classes OpenShell emits, requesting `profiles=trace` returns a schema without a `trace` property. A successful HTTP response alone therefore does not establish Trace support.

OpenShell extends the optional Trace profile to Base Event, Application Lifecycle, Authentication, Detection Finding, Device Config State Change, Network Activity, Process Activity, and SSH Activity. Those Trace schema variants contain a `$comment` that identifies the extension. They are official class exports plus an OpenShell extension, rather than unmodified official exports for those profile combinations.

For these eight classes, `schemas/trace_schema.py` copies the `trace` property and its complete definition closure (`trace`, `span`, `service`, and `key_value_object`) unchanged from the [official HTTP Activity export](https://schema.ocsf.io/schema/1.8.0/classes/http_activity?profiles=container,host,network_proxy,security_control,trace). It preserves every other class constraint, including required fields and rejection of undefined attributes. It rejects conflicting shared definitions, malformed or unresolved Trace definitions, unsupported versions, and invalid profile names or ordering. HTTP/API variants retain their native Trace exports after the same definition checks. The validator still selects an exact profile combination; it does not accept arbitrary additional fields or profiles.

Each of the 18 existing untraced profile combinations has a sibling with `+trace` in its name. To regenerate only these Trace variants from the repository root:

```shell
trace_schemas=()
for schema in crates/openshell-ocsf-validate/schemas/v1.8.0/*.json; do
  case "$schema" in *+trace.json) continue ;; esac
  trace_schemas+=("${schema%.json}+trace.json")
done
crates/openshell-ocsf-validate/schemas/update.sh "${trace_schemas[@]}"
```

This leaves the existing untraced schemas untouched. The updater uses `uv` for its Python formatting and composition steps. Trace outputs sort JSON keys so repeated exports of the same schema content produce the same bytes.

To reuse an already downloaded donor, set `OCSF_TRACE_SCHEMA_EXPORT` to the response file and `OCSF_TRACE_SCHEMA_SHA256` to its recorded SHA-256. The receipt must identify the exact OCSF 1.8.0 HTTP export URL above. The helper checks the hash and schema structure; it cannot independently establish the provenance or version of an arbitrary cache file because the schema server does not encode its version in `$id`. Preserve the download URL and response receipt alongside the hash.

Run the composition safeguards without a Rust build:

```shell
uv run --no-project python -m unittest discover -s crates/openshell-ocsf-validate/schemas -p 'test_trace_schema.py'
```

## Changing OCSF versions

Trace composition is deliberately restricted to OCSF 1.8.0. Review the newer version's profile applicability and definitions before updating `trace_schema.py` to permit it.

Each version's schemas live in their own directory, so a version change can land in steps:

1. Run `schemas/update.sh` with the current version's file names under `schemas/v<new>/`. Events labelled with the current version still validate against its schemas.
2. Change `openshell_ocsf::OCSF_VERSION`. Events now validate against the new schemas.
3. Delete the old version's directory.
