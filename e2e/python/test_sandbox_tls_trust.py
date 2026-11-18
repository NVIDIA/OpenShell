# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the supervisor CA trust files a default sandbox receives.

The files exist only in the sandbox runtime, which answers opens and metadata
calls on their exact paths. This verifies what TLS clients actually do with a
CA path: the stat and access checks `requests` and shell guards make, the
plain opens OpenSSL (Python `ssl`, the `openssl` CLI) makes, and that
the loaded bundle contains the supervisor CA alongside the system CAs.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox

_CA_DIR = "/run/openshell-supervisor-ca/material"

_CHECK_TRUST_FILES = textwrap.dedent(
    f"""
    import json, os, ssl, stat, subprocess

    ca_dir = {_CA_DIR!r}
    cert_path = os.environ["NODE_EXTRA_CA_CERTS"]
    bundle_path = os.environ["SSL_CERT_FILE"]
    assert cert_path == os.path.join(ca_dir, "ca.crt"), cert_path
    assert bundle_path == os.path.join(ca_dir, "ca-bundle.crt"), bundle_path
    for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"):
        assert os.environ[variable] == bundle_path, variable

    # What requests checks before it hands the path to OpenSSL.
    for path in (cert_path, bundle_path):
        assert os.path.exists(path), path
        assert not os.path.isdir(path), path
        info = os.stat(path)
        assert stat.S_ISREG(info.st_mode) and info.st_size > 0, path
        assert os.access(path, os.R_OK) and not os.access(path, os.W_OK), path
        with open(path, "rb") as handle:
            assert os.fstat(handle.fileno()).st_ino == info.st_ino, path
    # The directory itself is not provided.
    assert not os.path.exists(ca_dir), ca_dir

    with open(cert_path, "rb") as handle:
        cert = handle.read()
    with open(bundle_path, "rb") as handle:
        bundle = handle.read()
    assert cert.startswith(b"-----BEGIN CERTIFICATE-----"), cert[:40]
    assert cert.strip() in bundle, "bundle must contain the supervisor CA"
    assert len(bundle) > len(cert), "bundle must contain more than the supervisor CA"

    # Python ssl loads both through OpenSSL.
    supervisor_der = ssl.PEM_cert_to_DER_cert(cert.decode())
    context = ssl.create_default_context(cafile=bundle_path)
    loaded = context.get_ca_certs(binary_form=True)
    assert supervisor_der in loaded, "bundle must load the supervisor CA"
    assert len(loaded) > 1, "bundle must load the system CAs too"
    assert ssl.create_default_context(cafile=cert_path).get_ca_certs(binary_form=True) == [supervisor_der]

    # requests takes REQUESTS_CA_BUNDLE from the environment, then requires
    # the path to exist and not be a directory before handing it to OpenSSL.
    import requests
    url = "https://example.invalid/"
    verify = requests.Session().merge_environment_settings(url, {{}}, None, None, None)["verify"]
    assert verify == bundle_path, verify
    class Conn:
        pass
    conn = Conn()
    requests.adapters.HTTPAdapter().cert_verify(conn, url, verify, None)
    assert conn.ca_certs == bundle_path, conn.ca_certs

    # The openssl CLI and a shell guard read the same paths.
    verified = subprocess.run(
        ["openssl", "verify", "-CAfile", bundle_path, cert_path],
        capture_output=True, text=True, check=False,
    )
    assert verified.returncode == 0, verified.stderr
    guard = subprocess.run(
        ["sh", "-c", 'test -f "$SSL_CERT_FILE" && test -r "$SSL_CERT_FILE" && ! test -w "$SSL_CERT_FILE"'],
        check=False,
    )
    assert guard.returncode == 0, "shell file test"

    # Read-only to the workload.
    try:
        open(bundle_path, "wb")
    except PermissionError:
        pass
    else:
        raise AssertionError("trust bundle must not be writable")

    print(json.dumps({{"bundle_cas": len(loaded), "bundle_bytes": len(bundle)}}))
    """
)


def test_default_sandbox_exposes_a_consistent_supervisor_trust_bundle(
    sandbox: Callable[..., Sandbox],
    run_python: Callable[[Sandbox, str], tuple[int, str, str]],
) -> None:
    with sandbox(delete_on_exit=True) as sb:
        exit_code, stdout, stderr = run_python(sb, _CHECK_TRUST_FILES)
        assert exit_code == 0, f"stdout={stdout!r} stderr={stderr!r}"
        assert '"bundle_cas"' in stdout, stdout
