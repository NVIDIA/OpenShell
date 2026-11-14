# Windows signing candidate validation

Source: Windows-based backport PR #5558, commit `1c2521b7e839ffeb1ae0f37a77f5b9a700d3a536`.
Build: https://github.com/NVIDIA/OpenShell/actions/runs/43545453103

Both native GitHub runner builds, workspace regression suites, and executable launch checks passed. The candidate
ZIP hashes and detached GitHub provenance attestations were verified after download.
All ten executable/DLL hashes match the downloaded package manifests.
Each native architecture passed 6,659 workspace tests, with 43 skipped tests.
Unsupported Windows packages and platform-gated tests are outside that count.

ARM64: package checks, tamper rejection, default unsigned rejection, host capability
probe, initialization, gateway information, and PowerShell/TypeScript examples passed.
The real MXC E2E suite passed all seven scenarios, with zero failures or skips.
The additional injected-CA HTTPS scenario passed and verified the proxy certificate.
Product binary hashes were unchanged by testing. Python health: `blocked-native-dependency-installation`.
Native Windows ARM64 Python 3.14.5 could not install a compatible stable grpcio
wheel, so its Python health example did not run.

x64: native runner launch checks and local emulation package/launch checks passed.
The native host guard correctly rejected emulation as native x64 qualification.
Native x64 MXC runtime remains unqualified.

Privacy scanning passed for package files and nested SDK content. No local host
identities, private addresses, or runtime credentials are included in this report.
Detailed hashes and individual check results are in `validation-report.json`.

Exact-version dependency matching reduced advisory groups from 71 to 2, with no
candidate-only groups versus the recorded main baseline. The retained RSA and
SQLx/SQLite exceptions require review; these counts are not exploitability
claims or production-signing clearance.

The EXEs and DLLs are unsigned. Authenticode signing, signed-byte retesting, final
manifests/ZIPs, and new final archive attestations remain required. This external
validation report does not modify the attested candidate archives. See
`SIGNING-AND-PUBLISHING.md` for the remaining steps and publication process.
