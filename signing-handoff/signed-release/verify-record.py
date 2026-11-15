"""Verify the finalization record against original, GitHub-attested candidate bytes.

The signed package bytes and runtime validation were produced externally.
This workflow authenticates their supplied hash record; it does not rerun them.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

root = Path('signing-handoff/signed-release')
predicate = json.loads((root / 'signed-package-predicate.json').read_text())
report = json.loads((root / 'OpenShell-Windows-0.1.8-validation.json').read_text())
source = {'repository': 'https://github.com/NVIDIA/OpenShell', 'branch': 'windows',
          'commit': 'e39791be4f47ed6fb6357885ef42ca1339320679', 'versionStamp': '0.1.8'}
assert predicate['source'] == report['source'] == source
assert predicate['buildRun'] == report['buildRun'] == 'https://github.com/NVIDIA/OpenShell/actions/runs/43743849384'
assert predicate['buildAutomationCommit'] == report['buildAutomationCommit'] == 'f258c85b202a78e0b233f39cc8f991069ef509ab'
assert report['privacyScan'] == 'passed'
assert predicate['finalPackages'] == report['architectures']
assert report['signingVerification']['uniqueSignedPayloads'] == 28
assert report['signingVerification']['payloadIdentityPreserved'] is True
hashes = {}
for line in (root / 'OpenShell-Windows-0.1.8-SHA256SUMS').read_text().splitlines():
    digest, filename = line.split()
    assert re.fullmatch('[0-9a-f]{64}', digest) and filename not in hashes
    hashes[filename] = digest
assert set(hashes) == {'OpenShell-Windows-0.1.8-arm64.zip', 'OpenShell-Windows-0.1.8-x64.zip', 'OpenShell-Windows-0.1.8-validation.json'}
assert hashlib.sha256((root / 'OpenShell-Windows-0.1.8-validation.json').read_bytes()).hexdigest() == hashes['OpenShell-Windows-0.1.8-validation.json'] == predicate['validationReport']['sha256']
assert len(predicate['signedPayloads']) == 46
for arch in ('arm64', 'x64'):
    final = report['architectures'][arch]
    assert final['sha256'] == hashes[final['file']]
    assert final['authenticode'] == {'result': 'valid-timestamped', 'verifiedFiles': 23, 'publisher': 'NVIDIA Corporation'}
    assert final['signedPayloadHashesUnchangedAfterTests'] is True
    assert report['nativeRunnerTests'][arch] == {'passed': 6659, 'failed': 0, 'skipped': 43}
    candidate = Path(f'candidates/OpenShell-Windows-0.1.8-{arch}-unsigned-candidate.zip')
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == predicate['candidateArchives'][candidate.name]
    prefix = f'OpenShell-Windows-0.1.8-{arch}/'
    with zipfile.ZipFile(candidate) as z:
        manifest = json.loads(z.read(prefix + 'release-manifest.json'))
        assert manifest['source'] == source
        assert manifest['build']['workflowRun'] == report['buildRun']
        inputs = [r for r in predicate['signedPayloads'] if r['architecture'] == arch]
        assert len(inputs) == 23
        for item in inputs:
            assert item['payloadUnchanged'] is True
            assert re.fullmatch('[0-9a-f]{64}', item['signedSha256'])
            data = z.read(prefix + item['path'])
            if item['member']:
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
                    data = t.extractfile(item['member']).read()
            assert hashlib.sha256(data).hexdigest() == item['inputSha256']
assert report['architectures']['arm64']['nativeMxcRuntime'] == {'passed': 7, 'failed': 0, 'skipped': 0}
assert report['architectures']['arm64']['injectedCaHttps'] == {'passed': 1, 'failed': 0, 'skipped': 0}
assert report['architectures']['x64']['nativeMxcRuntime'] == 'unqualified-not-tested'
assert report['architectures']['x64']['launchEnvironment'] == 'x64-emulation-on-arm64'
print('Verified candidate provenance, input hashes, final checksum record, and external validation claims.')
