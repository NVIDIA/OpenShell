"""Package GitHub-built Windows candidates; never publish release assets."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import zipfile

ROOT = Path(os.environ['GITHUB_WORKSPACE'])
SOURCE = os.environ['SOURCE_SHA']
VERSION = '0.1.8'
RUN = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
TEMPLATES = Path(__file__).parent / 'templates'
PE_FILES = ('openshell.exe', 'openshell-gateway.exe', 'openshell-supervisor.exe', 'openshell-windows-sandbox.exe', 'libz3.dll')
Z3_HASHES = {
    'arm64': '8bf540e8ab0fc43462bd64ff85deb02b1c655bdac14f4f9c40187fedf9532e7c',
    'x64': 'f4ea9e799e13b64dc748415c5f7ec34fa0d885cb32e243ec991c973329bca1fb',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(path):
    """Reject machine paths and private files, including nested SDK contents."""
    needles = ('/Users/', '/home/runner/', 'C:\\Users\\', 'C:/Users/', 'D:\\a\\', 'D:/a/', 'C:\\a\\', 'C:/a/')
    encoded = [s.lower().encode(e) for s in needles for e in ('utf-8', 'utf-16-le')]

    def check(name, data):
        if name == 'libz3.dll' and hashlib.sha256(data).hexdigest() in Z3_HASHES.values():
            # The checksum-pinned upstream DLL contains public Z3 CI source paths.
            # Keep the official DLL unchanged; these are not local build/test paths.
            data = data.replace(b'D:\\a\\z3\\z3\\', b'/upstream-z3/')
        if any(n in data.lower() for n in encoded):
            raise ValueError(f'Unsanitized build path in {name}')
        if Path(name).suffix.lower() in ('.pdb', '.pem', '.key'):
            raise ValueError(f'Private build/runtime file: {name}')

    for item in path.rglob('*'):
        if not item.is_file():
            continue
        data = item.read_bytes()
        check(item.name, data)
        if item.suffix == '.whl':
            with zipfile.ZipFile(io.BytesIO(data)) as nested:
                for name in nested.namelist():
                    check(name, nested.read(name))
        if item.suffix == '.tgz':
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as nested:
                for member in nested:
                    if member.isfile():
                        check(member.name, nested.extractfile(member).read())


dist = ROOT / 'dist'
dist.mkdir()
checksums = []
inventory = []
for arch, machine in (('arm64', 0xAA64), ('x64', 0x8664)):
    kit = ROOT / 'kits' / f'OpenShell-Windows-{VERSION}-{arch}'
    shutil.copytree(TEMPLATES, kit)
    sboms = list((ROOT / 'source/deploy/sbom/output').glob('*.cdx.json'))
    assert len(sboms) == 1, 'Expected freshly generated source SBOM'
    sbom = json.loads(sboms[0].read_text())
    # Syft source locations describe public repository paths, never runner paths.
    sbom_text = json.dumps(sbom, indent=2).replace(str(ROOT / 'source'), '/src/openshell')
    (kit / 'sbom-source.cdx.json').write_text(sbom_text + '\n')
    readme = (kit / 'README.md').read_text().replace('(arm64)', f'({arch})').replace('@SOURCE_SHA@', SOURCE)
    (kit / 'README.md').write_text(readme)
    for name in ('LICENSE', 'THIRD-PARTY-NOTICES'):
        shutil.copy2(ROOT / 'source' / name, kit / name)
    shutil.copy2(ROOT / 'source/WINDOWS.md', kit / 'WINDOWS-UPSTREAM.md')
    native = ROOT / 'inputs' / f'native-{arch}'
    record = json.loads((native / 'build-record.json').read_text(encoding='utf-8-sig'))
    assert record['source'] == SOURCE and record['architecture'] == arch
    assert record['launchChecks'] == 'passed' and record['version'] == VERSION
    assert record['runner'].lower() == ('arm64' if arch == 'arm64' else 'x64')
    (kit / 'bin').mkdir()
    for name in PE_FILES:
        binary = native / name
        data = binary.read_bytes()
        offset = struct.unpack_from('<I', data, 0x3C)[0]
        assert data[:2] == b'MZ' and data[offset:offset+4] == b'PE\0\0'
        assert struct.unpack_from('<H', data, offset+4)[0] == machine, name
        entry = next(f for f in record['files'] if f['file'] == name)
        assert entry['sha256'] == digest(binary)
        if name == 'libz3.dll':
            assert digest(binary) == Z3_HASHES[arch], 'Unexpected upstream Z3 DLL'
        assert entry['signature'] == 'NotSigned', 'Unexpected signature state; review before packaging'
        shutil.copy2(binary, kit / 'bin' / name)
        inventory.append({'architecture': arch, 'file': f'{kit.name}/bin/{name}', 'sha256': digest(binary), 'authenticode': 'pending'})
    shutil.copytree(ROOT / 'inputs/sdk', kit / 'sdk')
    assert sorted(p.name for p in (kit / 'sdk').iterdir()) == ['nvidia-openshell-sdk-0.1.8.tgz', 'openshell-0.1.8-py3-none-any.whl']
    (kit / 'BUILD.md').write_text(f'''# Build record

Product source: NVIDIA/OpenShell windows branch, commit `{SOURCE}`.
Version: {VERSION}, stamped in the workspace manifest. This is different from the main-branch v0.1.8 tag.
Workflow: {RUN}
Automation commit: `{os.environ['GITHUB_SHA']}`.

The four executables were compiled on a native GitHub-hosted {arch} Windows runner using `{record['rust']}`, Visual Studio MSVC, and `mise run --skip-tools windows:build:{arch}`. The separately built validation fixture is excluded. Rust and native crypto source paths were remapped. The matching official Z3 5.1.0 DLL is included. Both SDKs were built from the same pinned source in this workflow.

The source SBOM was regenerated from this exact source commit in this workflow. It covers the broader source tree and is not an exact linked-binary inventory. License declarations require compliance review. Source locations are normalized.
''')
    (kit / 'VALIDATION.md').write_text('''# Candidate validation

Native runner builds and workspace regression tests passed. Package checks passed: all four executable launches/version checks, matching PE architectures, and staged binary SHA256 verification. Package assembly checks the inventory and scans nested SDK archives for build paths.

Runtime validation is performed after download against these exact archive and binary hashes. Consult the separate validation report; this ZIP does not claim local runtime tests have passed. x64 remains an unqualified runtime candidate until tested on a supported native x64 MXC host.

Authenticode signing and testing of the final signed bytes remain pending. Passing runtime scenarios does not establish the unverified isolation guarantees listed in KNOWN-LIMITATIONS.md.
''')
    (kit / 'SIGNING.md').write_text('''# Candidate signing

This package is prepared for Authenticode signing. Its EXEs and DLL are unsigned, so it is not a signed release. GitHub Actions attests the candidate ZIP after assembly; verify the detached bundle before using it:

```powershell
gh attestation verify <candidate.zip> --repo NVIDIA/OpenShell --signer-workflow NVIDIA/OpenShell/.github/workflows/windows-packages.yml --bundle github-attestation.sigstore.json
```

The workflow compiles the pinned Windows source and records its commit in BUILD.md and release-manifest.json. A GitHub attestation verifies provenance and package identity; it is not an Authenticode signature or runtime qualification.

For finalization, obtain valid timestamped Authenticode signatures on all four EXEs and libz3.dll, regenerate the file manifest, test the signed bytes, assemble new final ZIPs, and generate new checksums and GitHub attestations. The candidate attestation cannot authenticate modified ZIPs. Publish only the final approved packages.
''')
    manifest = {
        'schemaVersion': 1, 'version': VERSION, 'architecture': arch,
        'packageStatus': 'unsigned-candidate-not-release-ready',
        'source': {'repository': 'https://github.com/NVIDIA/OpenShell', 'branch': 'windows', 'commit': SOURCE, 'versionStamp': VERSION},
        'build': {'workflowRun': RUN, 'automationCommit': os.environ['GITHUB_SHA'], 'builtByThisWorkflow': True},
        'intendedRelease': {'repository': 'NVIDIA/OpenShell', 'tag': 'v0.1.8', 'matchesReleaseTagSource': False},
        'signing': {'authenticode': 'pending', 'githubArchiveAttestation': 'detached-verify-after-download'},
        'validation': {'nativeLaunchChecks': 'passed', 'runtimeReport': 'external-bound-to-sha256', 'finalSignedBytesValidated': False},
        'files': [{'path': p.relative_to(kit).as_posix(), 'size': p.stat().st_size, 'sha256': digest(p)} for p in sorted(kit.rglob('*')) if p.is_file()],
    }
    (kit / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    audit(kit)
    archive = dist / f'{kit.name}-unsigned-candidate.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(kit.rglob('*')):
            if path.is_file():
                output.write(path, path.relative_to(kit.parent).as_posix())
    checksums.append(f'{digest(archive)}  {archive.name}')
(dist / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
(dist / 'authenticode-signing-inventory.json').write_text(json.dumps({'source': SOURCE, 'workflowRun': RUN, 'files': inventory}, indent=2) + '\n')
print('\n'.join(checksums))
