# GB300 Windows ARM64 MXC qualification

This directory is the repository-owned qualification contract for NVBug 6643699.
It closes the test-plan ambiguity without treating it as a product defect.

[`gb300-woa.json`](gb300-woa.json) is the authoritative coverage matrix. Every
row declares its disposition, owner, architecture, hardware dependency,
prerequisites, command, pass criteria, skip policy, and required artifact roles.
[`validate.py`](validate.py) rejects a contract that weakens the required rows
and validates retained evidence by SHA256. [`run-gb300-woa.ps1`](run-gb300-woa.ps1)
executes the required native lane and produces that evidence.

## Scope decisions

- The release target is a **native GB300 Windows ARM64 host** using the MXC
  `process_container` backend. WSL and emulated/cross-built test execution do
  not receive credit.
- OpenClaw is the one required agent application because this repository owns
  its MXC launch and dynamic-forwarding harness. The caller must supply a
  versioned ARM64 Node.js binary and OpenClaw package.
- OpenShell does not choose or ship inference models. Model qualification and
  additional agent applications are optional, application-owned evidence and
  cannot replace an OpenShell/MXC gate.
- NemoClaw's native-x64 qualification guard is a separate application lane. It
  cannot satisfy any GB300 ARM64 row. The bundled Node/OpenClaw install helper
  is also x64-only; GB300 runs must not use its Node.js output.
- `isolation_session` is optional because it depends on the OS build,
  `IsoSessionApp.dll`, and the `wxc-exec` build. Its absence does not weaken the
  required ProcessContainer gate.
- MXC process-policy mapping, GPU passthrough, and interactive exec/connect are
  unsupported. Windows Docker, Kubernetes, Podman, and VM drivers remain
  unsupported. Host GPU presence is not evidence of MXC GPU passthrough.

## Coverage summary

The JSON manifest contains the full prerequisites, pass/fail criteria, and
artifact contract. This compact view makes the ownership boundary reviewable.

| Disposition | Coverage IDs | Owner boundary |
|---|---|---|
| Required | `contract-integrity`, `source-provenance`, `gb300-arm64-host`, `arm64-msvc-check`, `arm64-release-build`, `arm64-native-tests`, `arm64-unsupported-driver-contracts`, `processcontainer-real-mxc`, `processcontainer-policy-e2e`, `openclaw-arm64-forward` | OpenShell development owns repository tests; GB300 QA owns host execution and evidence; the agent-app owner supplies versioned ARM64 OpenClaw inputs |
| Optional | `isolation-session`, `provider-credential-injection`, `etw-ocsf-audit`, `local-inference-models`, `additional-agent-apps` | The named component or product owner decides whether to attach extra evidence |
| Unsupported | `wsl`, `windows-non-mxc-drivers`, `mxc-process-policy`, `mxc-gpu-passthrough`, `mxc-interactive-exec` | No qualification claim is permitted |
| Architecture-constrained | `nemoclaw-native-x64`, `node-openclaw-x64-installer`, `windows-x64-lanes` | Native x64 lanes stay separate and receive no GB300 ARM64 credit |

Required coverage is fail-closed: a missing prerequisite, `SKIP`, non-zero exit,
non-ARM64 result, missing artifact role, empty artifact, path outside the evidence
root, or SHA256 mismatch fails validation. Generic real-MXC developer tasks remain
skip-safe and are not qualification evidence.

## Validate the contract

Static validation and regression tests do not require Windows or MXC hardware:

```text
uv run python crates/openshell-driver-mxc/qualification/validate.py contract
uv run pytest python/gb300_mxc_qualification_test.py
```

## Execute on GB300

Start from a clean review commit based directly on the freshly fetched
`origin/windows` tip. Run from elevated native ARM64 PowerShell:

```powershell
$env:OPENSHELL_GB300_BASE_SHA = '<full origin/windows SHA>'
$env:OPENSHELL_GB300_HARDWARE_ATTESTATION = 'GB300'
$env:OPENSHELL_WXC_EXEC_PATH = 'C:\mxc-kit\bin\wxc-exec.exe'
$env:OPENSHELL_GB300_NODE_PATH = 'C:\path\to\arm64\node.exe'
$env:OPENSHELL_GB300_OPENCLAW_DIR = 'C:\path\to\node_modules\openclaw'
$env:OPENSHELL_GB300_EVIDENCE_DIR = 'D:\evidence\openshell-gb300-<run-id>'

mise run --skip-tools windows:qualify:mxc:gb300
```

The runner fetches `origin/windows`, rejects a moved or unrelated base, requires
a clean worktree, verifies the PE machine for `wxc-exec.exe` and `node.exe`, and
stages only tracked examples plus freshly built ARM64 binaries. It never treats
an existing source tree or an earlier result bundle as current evidence.

The evidence directory contains environment/source provenance, the MXC host
probe, command logs with timings, ARM64 binary hashes, the complete MXC policy
and OpenClaw bundles, `evidence.json`, and the final validation log. Do not put
provider credentials in command lines or retained files. Optional credential
coverage must use a scoped non-production credential and prove that retained
artifacts contain no secret value.
