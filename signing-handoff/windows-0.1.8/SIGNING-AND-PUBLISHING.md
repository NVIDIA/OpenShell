# Windows candidate handoff

The candidate ZIPs are built from NVIDIA/OpenShell's Windows-based PR #5558 at
the immutable backport commit recorded in `validation-report.json`, stamped 0.1.8. They are intended
for eventual addition to the existing `v0.1.8` release. Their source differs
from that release's main-branch tag. No release assets have been published.

GitHub provenance attestations authenticate the current candidate ZIPs.
Executable Authenticode signing is pending. The signing inventory lists all
ten PE files, grouped by architecture: four EXEs and `libz3.dll` per package.

## Binary signing

After the required license, vulnerability, and malware vetting is approved for
this exact source and dependency set, submit the architecture-specific binaries to
the approved Windows Authenticode signing service. Require timestamped publisher
signatures on every EXE and DLL. The PE input archive does not cover script
files; the applicable script-signing requirements must also be satisfied. Keep ARM64 and x64 outputs separate and retain
the pre-signing hashes to identify the submitted inputs.

Verify the returned files on Windows with `Get-AuthenticodeSignature` and
`signtool verify /pa /all /v`. Require valid signatures, the approved publisher,
and trusted timestamps. Replace only the corresponding files in each kit.

Signing changes the bytes. Regenerate the package file manifests, verify each
signed executable launches, and rerun package initialization and runtime checks
against the signed ARM64 payload. x64 remains an explicitly unqualified runtime
candidate until a supported native x64 MXC host validates it; emulation smoke
checks do not qualify native x64 runtime behavior.

Update signing and validation documentation, assemble new ZIPs, and calculate
new SHA256 values. Run a new GitHub attestation job for those final archive
hashes, retaining the original GitHub build provenance and explicitly recording
the later signing/finalization step. The candidate attestations cannot verify
modified ZIPs. Preserve the public Windows isolation limitations regardless of
test and signature outcomes.

## Publication

The source backport requires maintainer approval and integration into `windows`.
The two retained RSA and SQLx/SQLite advisory exceptions are not security clearance.
No production signing or release upload is authorized by the candidate report.

Adding portable ZIP assets does not require a package registry or a PR. Changes
to retained repository automation follow the normal contribution process.

Immediately before upload, verify repository write permission, release
mutability, final validation status, and that asset names do not already exist.
Use explicitly named final files and no `--clobber`:

```shell
gh release upload v0.1.8 --repo NVIDIA/OpenShell \
  OpenShell-Windows-0.1.8-arm64.zip \
  OpenShell-Windows-0.1.8-x64.zip \
  OpenShell-Windows-0.1.8-SHA256SUMS \
  OpenShell-Windows-0.1.8-attestations.jsonl
```

Publish an x64 candidate only with its unqualified status clearly identified;
do not describe it as runtime-qualified. Preserve all existing assets, checksums,
and release notes. Add a Windows note identifying the pinned Windows source and
its limitations. Download the published assets afresh and reverify their hashes
and attestations. Do not move the existing release tag.

Public packages and reports must exclude host identities, private addresses,
raw local logs, private keys, runtime state, PDBs, and test fixtures.
