# openshell-policy-schema

Canonical authored policy types, bounded YAML parsing, and pure validation.
Runtime enforcement and protobuf adaptation remain outside this crate.

The `yaml` module supplies the shared authored-data compatibility boundary used
by policy, provider-profile, and prover loaders and by CLI YAML output. Typed
maps and structs reject null rather than treating it as an empty object.
Options and untyped user-data values retain their ordinary null semantics.
Loaders reject duplicate mapping keys before decoding their typed schema.

Policy parsing retains its explicit resource budgets and field-path diagnostics.
YAML exports quote strings and mapping keys that legacy readers could interpret
as dates, numbers, or booleans, without changing actual numeric or boolean data.
Formatting the already-generated output does not impose new input-size limits.
