# Preserved pre-cache baseline

`pre-compatible.patch.gz` is the exact tracked working-tree diff captured before
the compatible config-revision iteration, against:

```text
e9f4a4269c8350f52ed827eb5d3588a20b25436d
```

It contains the earlier performance experiments, including the native provider
store. It does not contain the subsequent revision cache or six-byte classifier.
It is a source artifact, not a patch to apply to the current branch.

To reconstruct that control in a separate clean checkout at the base commit:

1. Decompress and apply it there:

   ```shell
   gzip -dc /path/to/this/branch/benchmarks/docker/baselines/pre-compatible.patch.gz | git apply -
   ```
2. Copy `crates/openshell-sandbox/src/provider_store.rs` from this branch into
   the control. This file was untracked when the baseline was captured and is
   unchanged by the compatible iteration.
3. For the compatible before/after **broker** comparison, also copy this
   branch's `crates/openshell-sandbox/src/perf.rs` and
   `crates/openshell-sandbox/src/bin/seccomp-perf.rs` into the control. Both
   variants must use this same extended measurement harness.
4. Build the control sandbox and harness with the same toolchain, target,
   profile, locked dependencies and feature set as the new runtime.

Use the **current branch's virtual-default gateway for both variants** of the
compatible Docker comparison. The old gateway in the reconstructed control
automatically selects native provider volumes on a sufficiently recent Docker
daemon, which would invalidate a comparison of virtual config delivery.

The historical PR #3832 comparison instead uses its exact upstream parent and
merge commits; see `../RESULTS-PR3832.md`. The two baselines answer different
questions.

Source and binary hashes, flags, container settings, raw samples, host-load
records and excluded pilot data are in
`../results/2026-11-16-compatible.json`. Rebuilt binaries or images on a new
machine may have different identities; record and pin those identities rather
than assuming the original host's image IDs are available.
