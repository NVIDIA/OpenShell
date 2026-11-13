# Windows signing candidate validation

Source: `windows` commit `5b9e5b91afb10afbce8d9be09e2513a7efc22a21`.
Build: https://github.com/NVIDIA/OpenShell/actions/runs/43341610986

Both native GitHub runner builds and executable launch checks passed. The candidate
ZIP hashes and detached GitHub provenance attestations were verified after download.
All ten executable/DLL hashes match the downloaded package manifests.

ARM64: package checks, tamper rejection, default unsigned rejection, host capability
probe, initialization, gateway information, and PowerShell/TypeScript examples passed.
The real MXC E2E suite passed all seven scenarios, with zero failures or skips.
Product binary hashes were unchanged by testing. Python health: `blocked-native-dependency-installation`.
Native Windows ARM64 Python 3.14.5 could not install a compatible stable grpcio
wheel, so its Python health example did not run.

x64: native runner launch checks and local emulation package/launch checks passed.
The native host guard correctly rejected emulation as native x64 qualification.
Native x64 MXC runtime remains unqualified.

Privacy scanning passed for package files and nested SDK content. No local host
identities, private addresses, or runtime credentials are included in this report.
Detailed hashes and individual check results are in `validation-report.json`.

The EXEs and DLLs are unsigned. Authenticode signing, signed-byte retesting, final
manifests/ZIPs, and new final archive attestations remain required. This external
validation report does not modify the attested candidate archives. See
`SIGNING-AND-PUBLISHING.md` for the remaining steps and publication process.
