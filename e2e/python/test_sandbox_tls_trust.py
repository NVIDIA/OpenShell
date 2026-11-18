# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the supervisor CA trust files a default sandbox receives.

Verifies that the workload finds the supervisor CA certificate and the
combined trust bundle where the TLS environment variables point, that metadata
checks, O_PATH and O_DIRECTORY opens, relative opens, and canonical opens keep
their native results, and that Python's TLS stack loads the bundle as a trust
store containing the supervisor CA.
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
    import json, os, ssl, stat

    ca_dir = {_CA_DIR!r}
    cert_path = os.environ["NODE_EXTRA_CA_CERTS"]
    bundle_path = os.environ["SSL_CERT_FILE"]
    assert cert_path == os.path.join(ca_dir, "ca.crt"), cert_path
    assert bundle_path == os.path.join(ca_dir, "ca-bundle.crt"), bundle_path
    for variable in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"):
        assert os.environ[variable] == bundle_path, variable

    # Metadata checks, path-only descriptors, and directory opens reach the
    # installed files and keep their native results.
    for path in (cert_path, bundle_path):
        assert os.path.exists(path), path
        assert stat.S_ISREG(os.stat(path).st_mode), path
        fd = os.open(path, os.O_PATH)
        try:
            assert stat.S_ISREG(os.fstat(fd).st_mode), path
        finally:
            os.close(fd)
        try:
            os.close(os.open(path, os.O_RDONLY | os.O_DIRECTORY))
        except NotADirectoryError:
            pass
        else:
            raise AssertionError(f"O_DIRECTORY must be ENOTDIR for {{path}}")

    # Canonical opens, a relative open, and an alias through ".." all read
    # the same bytes.
    with open(cert_path, "rb") as handle:
        cert = handle.read()
    with open(bundle_path, "rb") as handle:
        bundle = handle.read()
    os.chdir(ca_dir)
    with open("ca.crt", "rb") as handle:
        assert handle.read() == cert, "relative open"
    alias = os.path.join(ca_dir, "..", "material", "ca-bundle.crt")
    with open(alias, "rb") as handle:
        assert handle.read() == bundle, "alias open"

    assert cert.startswith(b"-----BEGIN CERTIFICATE-----"), cert[:40]
    assert cert.strip() in bundle, "bundle must contain the supervisor CA"
    assert len(bundle) > len(cert), "bundle must contain more than the supervisor CA"

    supervisor_der = ssl.PEM_cert_to_DER_cert(cert.decode())
    context = ssl.create_default_context(cafile=bundle_path)
    loaded = context.get_ca_certs(binary_form=True)
    assert supervisor_der in loaded, "bundle must load the supervisor CA"
    assert len(loaded) > 1, "bundle must load the system CAs too"
    supervisor_only = ssl.create_default_context(cafile=cert_path)
    assert supervisor_only.get_ca_certs(binary_form=True) == [supervisor_der]

    # The files are read-only to the workload.
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
