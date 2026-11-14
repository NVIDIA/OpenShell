"""Bind an external validation report to unchanged, previously attested ZIPs."""
from pathlib import Path
import hashlib
import json
import shutil
import zipfile

destination = Path('handoff')
reports = Path('signing-handoff/windows-0.1.8')
report = json.loads((reports / 'validation-report.json').read_text())
assert report['source']['commit'] == '1c2521b7e839ffeb1ae0f37a77f5b9a700d3a536'
assert report['workflowRun'] == 'https://github.com/NVIDIA/OpenShell/actions/runs/43545453103'
assert report['authenticode'] == 'pending' and report['finalSignedBytesValidated'] is False
assert report['architectures']['arm64']['mxcE2E'] == {'passed': 7, 'failed': 0, 'skipped': 0, 'binaryHashesUnchanged': True}
assert report['architectures']['arm64']['injectedCaHttps'] == {'passed': 1, 'failed': 0, 'skipped': 0, 'binaryHashesUnchanged': True}
assert set(report['nativeRunnerTests']) == {'arm64', 'x64'}
assert all(r['passed'] == 6659 and r['failed'] == 0 and r['skipped'] == 43 for r in report['nativeRunnerTests'].values())
assert report['architectures']['x64']['nativeMxcRuntime'] == 'unqualified-not-tested'
assert report['afterTesting'] == {'allManifestFilesUnchanged': True, 'testFixturesExcluded': True}
inventory = json.loads((destination / 'authenticode-signing-inventory.json').read_text())
assert len(inventory['files']) == 10
inputs = destination / 'OpenShell-Windows-0.1.8-authenticode-inputs.zip'
with zipfile.ZipFile(inputs, 'w', zipfile.ZIP_DEFLATED) as output:
    for arch in ('arm64', 'x64'):
        record = report['architectures'][arch]
        archive = destination / f'OpenShell-Windows-0.1.8-{arch}-unsigned-candidate.zip'
        assert archive.name == record['archive']
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == record['archiveSha256']
        with zipfile.ZipFile(archive) as original:
            manifest = json.loads(original.read(f'OpenShell-Windows-0.1.8-{arch}/release-manifest.json'))
            assert manifest['source']['commit'] == report['source']['commit']
            assert manifest['build']['workflowRun'] == report['workflowRun']
            actual = {f['file']: f['sha256'] for f in record['binaries']}
            entries = [entry for entry in inventory['files'] if entry['architecture'] == arch]
            assert len(entries) == 5
            for entry in entries:
                data = original.read(entry['file'])
                name = Path(entry['file']).name
                assert hashlib.sha256(data).hexdigest() == entry['sha256'] == actual[name]
                output.writestr(f'{arch}/{name}', data)
    output.write(destination / 'authenticode-signing-inventory.json', 'authenticode-signing-inventory.json')
(destination / 'SIGNING-INPUTS-SHA256SUMS').write_text(f'{hashlib.sha256(inputs.read_bytes()).hexdigest()}  {inputs.name}\n')
for name in ('validation-report.json', 'VALIDATION.md', 'SIGNING-AND-PUBLISHING.md'):
    shutil.copy2(reports / name, destination / name)
(destination / 'HANDOFF.md').write_text('''# Validated signing handoff

The two candidate ZIPs and their GitHub attestations are unchanged from the original
Windows runner build. This workflow verifies those attestations and matches the
external validation report to the exact archive and executable hashes. It does
not perform the external runtime tests itself or sign executable files.

The Authenticode inputs ZIP contains the ten EXE/DLL signing inputs and their
inventory. Its contents are checked against the attested product archives.
The original GitHub attestation covers the candidate ZIPs, not this report or
the separately assembled signing-inputs ZIP.

See VALIDATION.md for passed checks and remaining gaps, and
SIGNING-AND-PUBLISHING.md for signing, retesting, and publication steps.
''')
print('Original attestations preserved; external validation hashes and ten signing inputs checked')
