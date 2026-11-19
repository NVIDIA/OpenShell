# Windows signing candidates

`windows-packages.yml` builds native ARM64 and x64 candidates from its pinned
`windows` source commit using the existing Windows mise tasks. SDKs are built
from that same commit.

The workflow uploads separate product inputs, validation fixtures, and candidate
ZIPs with GitHub provenance attestations. Build and package failures are blocking.
It does not publish a release or sign executable files with Authenticode.

Download the candidate artifact and verify its ZIP attestations before testing.
Run the existing MXC E2E harness against the extracted `bin` directory, using the
separate fixture only during validation. Do not rebuild product binaries locally.
Keep local reports separate from the ZIPs and identify tested bytes by SHA256.
Do not upload raw local logs, machine identities, generated keys, or runtime state.

The four executables embed the CRT and the gateway embeds Z3. The build audits
normal and delayed PE imports and excludes standalone Z3 DLLs. Preserve the Z3
license and pinned dependency record. Path-remapping rustflags must also include
`-C target-feature=+crt-static` because environment flags override Cargo config.
These release builds use `OPENSHELL_WINDOWS_Z3_SOURCE=1` with MSVC C++ path
remapping. The default pinned prebuilt libraries embed their producer's absolute
source paths, which fail the release privacy check. Source mode retains the
repository's Z3 version and verified source checksum.

Authenticode signing changes binary hashes. After signing all EXEs, PowerShell
scripts, and SDK JavaScript files,
update manifests and checksums, retest, and attest the new final archives before
publishing. Candidate checks do not qualify the final signed bytes or the known
Windows isolation limitations. Native x64 runtime qualification remains pending.

Each run builds its own immutable Git commit, runs native workspace regression
tests on both architectures, checks the TypeScript SDK, and generates a new source
SBOM before attesting the candidate archives. The SBOM covers the broader source
tree; it is not an exact linked-library inventory or compliance approval.

`windows-signing-handoff.yml` retrieves a pinned successful candidate run,
verifies its ZIP attestations, checks the supplied external signing and validation
records, and attests the final signed archive checksums. Its custom predicate
states that Authenticode signing, final package assembly, and runtime validation
occurred externally. The workflow uploads the final verification bundle; it does
not perform those external operations or upload release assets.
