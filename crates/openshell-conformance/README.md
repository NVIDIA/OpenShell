# Conformance test support

This crate provides the existing CLI command runner, bounded polling, structured
output parsing, diagnostics, and explicit resource cleanup for conformance tests.

Conformance stories and their assertions live directly in
[`e2e/suites/conformance`](../../e2e/suites/conformance/README.md). This crate does
not define scenarios or maintain a registry; Cargo discovers the tests.

Runner consolidation with the existing Rust e2e harness remains separate work.
