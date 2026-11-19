# Policy conformance

Runs equivalent YAML/Rego and Cedar scenarios through policy authorization,
provider credential selection, DNS, destination validation, and protocol relays.
The package is a workspace member, so normal workspace tests and CI include it.

```shell
cargo test --locked -p openshell-policy-conformance
```

`src/conformance/expected.json` records each scenario's expected outcome. A string
applies to both backends; an object records explicit `yaml` and `cedar` outcomes
for a documented difference. Each backend is checked independently, so both
engines returning the same wrong decision still fails. The initial expectations
preserve the passing suite's behavior, including its original explicit assertions.
Review expectation changes as policy behavior changes; tests never regenerate them.

The `ported_*` modules retain the source tests' names and behavior. Cedar language
rejection checks remain where they explain a conformance difference. The separate
`cedar_integration` module checks cross-layer endpoint identity and query decoding.
Cedar implementation tests remain in the Cedar crates, and network unit tests
remain in networking.

All dependencies are test-only. Networking's `test-support` feature exposes
engine-neutral probes without exposing internal DNS stores or credential fields.
No product crate depends on this package.
