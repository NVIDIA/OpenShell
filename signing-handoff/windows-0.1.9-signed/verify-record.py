"""Verify the supplied finalization record against GitHub-attested candidates.

Signing, final archive assembly and runtime tests occurred externally. This
workflow verifies the supplied records and attests their final checksums.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

root = Path('signing-handoff/windows-0.1.9-signed')
predicate = json.loads((root / 'signed-package-predicate.json').read_text())
report = json.loads((root / 'OpenShell-Windows-0.1.9-validation.json').read_text())
source = {'repository': 'https://github.com/NVIDIA/OpenShell', 'branch': 'windows',
          'commit': '7e4e113e3249238b61db71947c4b79b2d7a247e3', 'versionStamp': '0.1.9'}
assert predicate['source'] == report['source'] == source
assert predicate['buildRun'] == report['buildRun'] == 'https://github.com/NVIDIA/OpenShell/actions/runs/44465275559'
assert predicate['buildAutomationCommit'] == report['buildAutomationCommit'] == '4d7c622fa4886567687eca7cc3f42271b0d6edf1'
assert report['privacyScan'] == 'passed'
assert predicate['finalPackages'] == report['architectures']
assert report['signingVerification']['payloadIdentityPreserved'] is True
unique = {(p['inputSha256'], Path(p['member'] or p['path']).suffix) for p in predicate['signedPayloads']}
assert len(unique) == report['signingVerification']['uniqueSignedPayloads']
assert sum(suffix == '.exe' for _, suffix in unique) == 8
assert not any(suffix == '.dll' for _, suffix in unique)
hashes = {}
for line in (root / 'OpenShell-Windows-0.1.9-SHA256SUMS').read_text().splitlines():
    digest, filename = line.split()
    assert re.fullmatch('[0-9a-f]{64}', digest) and filename not in hashes
    hashes[filename] = digest
assert set(hashes) == {'OpenShell-Windows-0.1.9-arm64.zip', 'OpenShell-Windows-0.1.9-x64.zip', 'OpenShell-Windows-0.1.9-validation.json'}
assert hashlib.sha256((root / 'OpenShell-Windows-0.1.9-validation.json').read_bytes()).hexdigest() == hashes['OpenShell-Windows-0.1.9-validation.json'] == predicate['validationReport']['sha256']
for arch in ('arm64', 'x64'):
    final = report['architectures'][arch]
    assert final['sha256'] == hashes[final['file']]
    count = report['signingVerification']['signedFilesPerPackage'][arch]
    assert final['authenticode'] == {'result': 'valid-timestamped', 'verifiedFiles': count, 'publisher': 'NVIDIA Corporation'}
    assert final['signedPayloadHashesUnchangedAfterTests'] is True
    assert final['runtimeLinkage'] == {'crt': 'static', 'z3': 'static', 'z3DllIncluded': False, 'signedPeImportAudit': 'passed'}
    assert report['nativeRunnerTests'][arch]['failed'] == 0
    assert report['nativeRunnerTests'][arch]['passed'] > 0
    assert report['nativeRunnerTests'][arch]['skipped'] >= 0
    candidate = Path(f'candidates/OpenShell-Windows-0.1.9-{arch}-unsigned-candidate.zip')
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == predicate['candidateArchives'][candidate.name]
    prefix = f'OpenShell-Windows-0.1.9-{arch}/'
    with zipfile.ZipFile(candidate) as z:
        manifest = json.loads(z.read(prefix + 'release-manifest.json'))
        assert manifest['source'] == source
        assert manifest['build']['workflowRun'] == report['buildRun']
        assert manifest['build']['runtime'] == 'static-crt-and-z3'
        assert manifest['build']['staticRuntimeAudit'] == 'passed'
        assert manifest['build']['z3BuildMode'] == 'pinned-source-with-path-remapping'
        assert not any(name.lower().endswith('.dll') for name in z.namelist())
        expected = {}
        for entry in manifest['files']:
            path = entry['path']
            data = z.read(prefix + path)
            if path.endswith(('.exe', '.ps1', '.js')):
                expected[(path, None)] = hashlib.sha256(data).hexdigest()
            elif path.endswith('.tgz'):
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
                    for member in t:
                        if member.isfile() and member.name.endswith('.js'):
                            expected[(path, member.name)] = hashlib.sha256(t.extractfile(member).read()).hexdigest()
        inputs = [p for p in predicate['signedPayloads'] if p['architecture'] == arch]
        assert len(inputs) == count == len(expected)
        assert {(p['path'], p['member']): p['inputSha256'] for p in inputs} == expected
        assert all(p['payloadUnchanged'] is True and re.fullmatch('[0-9a-f]{64}', p['signedSha256']) for p in inputs)
assert report['architectures']['arm64']['nativeMxcRuntime'] == {'passed': 9, 'failed': 0, 'skipped': 0}
assert report['architectures']['arm64']['injectedCaHttps'] == {'passed': 1, 'failed': 0, 'skipped': 0}
assert report['architectures']['arm64']['gatewayKillAndRestart'] == 'passed'
assert report['architectures']['x64']['nativeMxcRuntime'] == 'unqualified-not-tested'
assert report['architectures']['x64']['launchEnvironment'] == 'x64-emulation-on-arm64'
assert all(report['arm64PackageExamples'][key] == 'passed' for key in ('initialization', 'gatewayStartAndInfo', 'powershellHarness', 'typescriptHarness'))
print('Verified original candidate inputs, static-runtime records, signing inventory and final checksum record.')
