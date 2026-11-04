# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_proto_compatibility as compatibility

TAG = "v0.1.6-pre.7"
REASON = "Release captain accepted the protobuf changes."


@pytest.mark.parametrize(
    ("ref", "exception_tag", "reason", "expected"),
    [
        (f"refs/tags/{TAG}", TAG, REASON, True),
        ("refs/tags/v0.1.6-pre.8", "v0.1.6-pre.8", REASON, True),
        ("refs/tags/v0.1.6-pre.12", "v0.1.6-pre.12", REASON, True),
        ("refs/tags/v0.1.6-pre.8", "", "", False),
        ("refs/tags/v0.1.7-pre.1", "", "", False),
        ("refs/tags/v0.2.0-pre.1", "", "", False),
        (f"refs/tags/{TAG}", "", "", False),
        ("refs/tags/v0.1.6-pre.8", TAG, REASON, ValueError),
        ("refs/tags/v0.1.6", "v0.1.6", REASON, ValueError),
        ("refs/heads/main", TAG, REASON, ValueError),
        (f"refs/tags/{TAG}", TAG, " ", ValueError),
    ],
)
def test_exception_scope(monkeypatch, ref, exception_tag, reason, expected):
    monkeypatch.setenv("PROTO_COMPATIBILITY_EXCEPTION_TAG", exception_tag)
    monkeypatch.setenv("PROTO_COMPATIBILITY_EXCEPTION_REASON", reason)
    monkeypatch.setattr(sys, "argv", ["check", ref])
    with (
        patch.object(compatibility, "git", side_effect=[ref, "candidate-sha"]),
        patch.object(
            compatibility, "train_policy", return_value=("v0.1.5", "v0.1.6", False)
        ),
        patch.object(compatibility, "compare", return_value=0) as compare,
    ):
        if expected is ValueError:
            with pytest.raises(ValueError):
                compatibility.main()
            compare.assert_not_called()
        else:
            assert compatibility.main() == 0
            assert compare.call_args.args[2] is expected


@pytest.mark.parametrize(
    ("allows_breaks", "exit_code", "expected"),
    [(False, 100, 100), (True, 100, 0), (True, 1, 1), (True, 0, 0)],
)
def test_exception_only_accepts_breaking_diagnostics(
    allows_breaks, exit_code, expected
):
    with (
        patch.object(compatibility, "export_proto"),
        patch.object(
            compatibility.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], 0),
                subprocess.CompletedProcess([], exit_code, stdout="", stderr=""),
            ],
        ) as run,
    ):
        assert compatibility.compare("candidate", "baseline", allows_breaks) == expected
        assert [call.args[0][1] for call in run.call_args_list] == [
            "build",
            "build",
            "breaking",
        ]


@pytest.mark.parametrize("failed_snapshot", [0, 1])
def test_exception_does_not_accept_invalid_protobufs(failed_snapshot):
    results = [subprocess.CompletedProcess([], 0)] * failed_snapshot
    results.append(subprocess.CalledProcessError(100, ["buf", "build"]))
    with (
        patch.object(compatibility, "export_proto"),
        patch.object(compatibility.subprocess, "run", side_effect=results) as run,
        pytest.raises(subprocess.CalledProcessError),
    ):
        compatibility.compare("candidate", "baseline", True)
    assert run.call_count == failed_snapshot + 1


@pytest.mark.skipif(shutil.which("buf") is None, reason="Buf is not installed")
@pytest.mark.parametrize("allows_breaks", [False, True])
def test_real_buf_field_rename(monkeypatch, allows_breaks):
    def export_fixture(ref, destination):
        (destination / "proto").mkdir(parents=True)
        (destination / "buf.yaml").write_text(
            "version: v2\nmodules:\n  - path: proto\nbreaking:\n  use:\n    - FILE\n"
        )
        field = "old_name" if ref == "baseline" else "new_name"
        (destination / "proto" / "test.proto").write_text(
            'syntax = "proto3";\npackage test.v1;\n'
            f"message Request {{ bool {field} = 3; }}\n"
        )

    monkeypatch.setattr(compatibility, "export_proto", export_fixture)
    assert compatibility.compare("candidate", "baseline", allows_breaks) == (
        0 if allows_breaks else 100
    )


@pytest.mark.parametrize("exception", [False, True])
@pytest.mark.parametrize("proto_result", ["success", "failure", "skipped"])
@pytest.mark.parametrize("tag", [TAG, "v0.1.6-pre.8"])
def test_qualification_records_exception_without_bypassing_results(
    tmp_path, exception, proto_result, tag
):
    output = tmp_path / "qualification.json"
    env = {
        **os.environ,
        "RELEASE_TAG": tag,
        "SOURCE_SHA": "candidate-sha",
        "IS_PRERELEASE": "true",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "NVIDIA/OpenShell",
        "PROTO_COMPATIBILITY_RESULT": proto_result,
        "PROTO_COMPATIBILITY_EXCEPTION_TAG": tag if exception else "",
        "PROTO_COMPATIBILITY_EXCEPTION_REASON": REASON,
    }
    for suite in (
        "SECURITY",
        "CONFORMANCE",
        "FEATURE_INTEGRATION",
        "DOCKER_E2E",
        "VM_E2E",
    ):
        env[f"{suite}_RESULT"] = "success"
    subprocess.run(
        [
            "bash",
            str(Path(__file__).with_name("generate-qualification-summary.sh")),
            str(output),
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(output.read_text())
    assert summary["current_profile_passed"] is (proto_result == "success")
    assert summary["exceptions"] == (
        [{"suite": "protobuf_compatibility", "tag": tag, "reason": REASON}]
        if exception
        else []
    )
