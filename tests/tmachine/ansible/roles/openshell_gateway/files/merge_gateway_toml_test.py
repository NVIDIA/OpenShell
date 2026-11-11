# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("merge-gateway-toml.py")
BASE = '[openshell]\nversion = 2\n\n[openshell.drivers.podman]\n# keep\nhealth_check_interval_secs = 10\n'


def merge(tmp_path, base, overrides, default=None):
    base_file, override_file = tmp_path / "gateway.toml", tmp_path / "overrides.toml"
    if base is not None:
        base_file.write_text(base)
    override_file.write_text(overrides)
    args = [sys.executable, str(SCRIPT), str(base_file), str(override_file)]
    if default is not None:
        default_file = tmp_path / "default.toml"
        default_file.write_text(default)
        args += ["--default", str(default_file)]
    run = subprocess.run(args, capture_output=True, text=True)
    return run, base_file


def test_replaces_and_preserves_comments(tmp_path):
    run, base = merge(tmp_path, BASE, '[openshell.drivers.podman]\nhealth_check_interval_secs = 15\nuserns = "keep-id"\n')
    assert run.returncode == 0, run.stderr
    text = base.read_text()
    assert "# keep" in text
    assert tomllib.loads(text)["openshell"]["drivers"]["podman"] == {
        "health_check_interval_secs": 15,
        "userns": "keep-id",
    }


def test_idempotent(tmp_path):
    overrides = '[openshell.drivers.podman]\nuserns = "private"\nuidmap = ["0:0:1",\n  "1:1:65535"]\n'
    merge(tmp_path, BASE, overrides)
    first = (tmp_path / "gateway.toml").read_text()
    run, base = merge(tmp_path, first, overrides)
    assert run.returncode == 0 and base.read_text() == first


def test_array_of_tables_header_is_a_boundary(tmp_path):
    base = (
        "[openshell.drivers.podman]\nhealth_check_interval_secs = 10\n"
        '[[openshell.supervisor.middleware]]\nname = "local-guard"\n'
        'grpc_endpoint = "https://127.0.0.1:50051"\n'
    )
    run, out = merge(tmp_path, base, "[openshell.drivers.podman]\nhealth_check_interval_secs = 15\n")
    assert run.returncode == 0, run.stderr
    parsed = tomllib.loads(out.read_text())["openshell"]
    assert parsed["drivers"]["podman"] == {"health_check_interval_secs": 15}
    assert parsed["supervisor"]["middleware"] == [
        {"name": "local-guard", "grpc_endpoint": "https://127.0.0.1:50051"}
    ]


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_key_is_applied(tmp_path, quote):
    run, base = merge(tmp_path, BASE, f'[openshell.drivers.podman]\n{quote}userns{quote} = "keep-id"\n')
    assert run.returncode == 0, run.stderr
    assert tomllib.loads(base.read_text())["openshell"]["drivers"]["podman"]["userns"] == "keep-id"


@pytest.mark.parametrize(
    "overrides",
    [
        '[openshell.drivers.podman]\nuserns "keep-id"\n',
        '[openshell.drivers.podman]\nuserns = "keep-id\n',
        '[[openshell.supervisor.middleware]]\nname = "x"\n',
        'userns = "keep-id"\n',
    ],
)
def test_rejects_unusable_overrides_and_leaves_base(tmp_path, overrides):
    run, base = merge(tmp_path, BASE, overrides)
    assert run.returncode != 0
    assert base.read_text() == BASE


def test_dotted_key_not_silently_dropped(tmp_path):
    run, base = merge(tmp_path, BASE, "[openshell.drivers]\npodman.userns = \"auto\"\n")
    if run.returncode == 0:
        assert tomllib.loads(base.read_text())["openshell"]["drivers"]["podman"]["userns"] == "auto"
    else:
        assert base.read_text() == BASE


def test_creates_from_default_else_minimal(tmp_path):
    run, base = merge(tmp_path, None, '[openshell.drivers.podman]\nuserns = "auto"\n', default=BASE)
    assert run.returncode == 0 and "health_check_interval_secs = 10" in base.read_text()
    other = tmp_path / "other"
    other.mkdir()
    run, base = merge(other, None, '[openshell.drivers.podman]\nuserns = "auto"\n')
    parsed = tomllib.loads(base.read_text())
    assert parsed["openshell"]["version"] == 2
