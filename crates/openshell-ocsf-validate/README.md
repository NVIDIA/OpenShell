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

## Changing OCSF versions

Each version's schemas live in their own directory, so a version change can land in steps:

1. Run `schemas/update.sh` with the current version's file names under `schemas/v<new>/`. Events labelled with the current version still validate against its schemas.
2. Change `openshell_ocsf::OCSF_VERSION`. Events now validate against the new schemas.
3. Delete the old version's directory.
