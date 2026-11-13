# Windows signing candidates

`windows-packages.yml` builds native ARM64 and x64 candidates from its pinned
`windows` source commit using the existing Windows mise tasks. SDKs are built
from that same commit. The packaging branch changes automation only.

The workflow uploads separate product inputs, validation fixtures, and candidate
ZIPs with GitHub provenance attestations. Build and package failures are blocking.
It does not publish a release or sign executable files with Authenticode.

Download the candidate artifact and verify its ZIP attestations before testing.
Run the existing MXC E2E harness against the extracted `bin` directory, using the
separate fixture only during validation. Do not rebuild product binaries locally.
Keep local reports separate from the ZIPs and identify tested bytes by SHA256.
Do not upload raw local logs, machine identities, generated keys, or runtime state.

Authenticode signing changes binary hashes. After signing all EXEs and DLLs,
update manifests and checksums, retest, and attest the new final archives before
publishing. Candidate checks do not qualify the final signed bytes or the known
Windows isolation limitations. Native x64 runtime qualification remains pending.

The source SBOM template was generated from the pinned source commit, with
source paths normalized. It retains 22 unresolved license declarations and is
not an exact linked-library inventory. Refresh it when changing the source pin.
