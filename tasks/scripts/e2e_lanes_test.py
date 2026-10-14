# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise family dispatch and guard the existing CI target/coverage contract."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


def workflow(name):
    # BaseLoader leaves the Actions `on` key and expressions as strings.
    return yaml.load((WORKFLOWS / name).read_text(), Loader=yaml.BaseLoader)


def matrix_rows(job, profile="core"):
    expression = job["strategy"]["matrix"]["include"]
    if isinstance(expression, list):
        return expression
    if "inputs.profile" in expression:
        for candidate, rows in re.findall(
            r"inputs.profile == '([^']+)' && '([^']+)'", expression
        ):
            if profile == candidate:
                return json.loads(rows)
        return json.loads(re.search(r"\|\|\s+'([^']+)'\) }}$", expression)[1])
    return json.loads(re.search(r"fromJSON\('([^']+)'\)", expression)[1])


def family_targets(family, profile):
    """Expand the actual family matrices into identifiable coverage targets."""
    targets = set()
    for driver, job in workflow(f"e2e-{family}.yml")["jobs"].items():
        if not job.get("uses", "").startswith("./.github/workflows/e2e-"):
            continue
        profiles = re.findall(r"inputs.profile == '([^']+)'", job["if"])
        if profile not in profiles:
            continue
        if driver == "gpu":
            targets.add("gpu-e2e")
            continue
        for row in matrix_rows(job, profile):
            if driver == "kubernetes":
                task = row["e2e-task"]
                if task == "e2e:kubernetes":
                    key = (
                        "kubernetes-ha-e2e"
                        if profile == "kubernetes-ha"
                        else f"kubernetes-{row['agent-sandbox-version']}-e2e"
                    )
                else:
                    key = task.removeprefix("e2e:").replace(":", "-") + "-e2e"
                    key = key.replace("credential-drivers", "credentials")
            else:
                key = driver + (
                    "-external-driver-e2e" if row["variant"] == "external" else "-e2e"
                )
            targets.add(key)
    return targets


@pytest.fixture
def cargo_stub(tmp_path):
    cargo = tmp_path / "cargo"
    cargo.write_text(
        "#!/bin/bash\n"
        'printf "%s\\n" "$*" >> "$TEST_CARGO_LOG"\n'
        'if [[ "$*" == *"suites/conformance"* ]]; then\n'
        '  exit "${TEST_CONFORMANCE_EXIT:-0}"\n'
        "fi\n"
        'exit "${TEST_DRIVER_EXIT:-0}"\n'
    )
    cargo.chmod(0o755)
    log = tmp_path / "cargo.log"
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENSHELL_")}
    env.update(
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        TEST_CARGO_LOG=str(log),
        OPENSHELL_BIN="/usr/bin/true",
    )
    return env, log


def run_harness(driver, family, cargo_stub, **overrides):
    env, log = cargo_stub
    env = env | {"OPENSHELL_E2E_TEST_FAMILY": family} | overrides
    if driver == "vm":
        # Execute the actual test phase, after provisioning, with fake Cargo and
        # provider setup. VM process startup itself requires a Linux/KVM runner.
        script = (ROOT / "e2e/rust/e2e-vm.sh").read_text()
        tests = script[script.index('if [ "${E2E_RUN_CONFORMANCE}" = "1" ]; then') :]
        command = [
            "bash",
            "-c",
            "set -euo pipefail\n"
            f'ROOT="{ROOT}"\n'
            'CLI_BIN="$OPENSHELL_BIN"\n'
            'source "$ROOT/e2e/support/conformance.sh"\n'
            'source "$ROOT/e2e/support/test-family.sh"\n'
            'E2E_FEATURES="${OPENSHELL_E2E_VM_FEATURES-e2e-vm}"\n'
            'E2E_TEST_OVERRIDE="${OPENSHELL_E2E_VM_TEST:-}"\n'
            "OPENSHELL_GATEWAY_ENDPOINT=http://fixture\n"
            'e2e_select_test_family "$E2E_FEATURES"\n'
            "e2e_import_example_provider_profiles() { return 0; }\n" + tests,
        ]
    else:
        command = [
            "bash",
            f"e2e/rust/e2e-{driver}.sh",
            f"__openshell_run_{driver}_e2e",
        ]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    calls = log.read_text().splitlines() if log.exists() else []
    return result, calls


@pytest.mark.parametrize("driver", ["docker", "podman", "kubernetes", "vm"])
@pytest.mark.parametrize("family", ["all", "conformance", "drivers"])
def test_harness_runs_only_selected_suites(driver, family, cargo_stub):
    result, calls = run_harness(driver, family, cargo_stub)
    assert result.returncode == 0, result.stderr
    conformance = [call for call in calls if "suites/conformance" in call]
    runtime = [call for call in calls if "e2e/rust/Cargo.toml" in call]
    assert len(conformance) == (0 if family == "drivers" else 1)
    assert len(runtime) == (
        0 if family == "conformance" else 5 if driver == "vm" else 1
    )
    if runtime and driver == "vm":
        assert [call.split("--test ")[1].split()[0] for call in runtime] == [
            "ephemeral_cleanup",
            "host_gateway_alias",
            "vm_overlay",
            "vm_gateway_start",
            "vm_corporate_proxy",
        ]


@pytest.mark.parametrize("driver", ["docker", "podman", "kubernetes", "vm"])
@pytest.mark.parametrize(
    "family,override",
    [
        ("all", {"TEST_CONFORMANCE_EXIT": "19"}),
        ("drivers", {"TEST_DRIVER_EXIT": "23"}),
    ],
)
def test_suite_failures_propagate(driver, family, override, cargo_stub):
    result, calls = run_harness(driver, family, cargo_stub, **override)
    assert result.returncode != 0
    if family == "all":
        assert len(calls) == 1, "failed conformance must not be masked by a later pass"


@pytest.mark.parametrize("driver", ["docker", "podman", "kubernetes"])
def test_legacy_empty_features_run_conformance_only(driver, cargo_stub):
    key = f"OPENSHELL_E2E_{driver.upper()}_FEATURES"
    result, calls = run_harness(driver, "all", cargo_stub, **{key: ""})
    assert result.returncode == 0, result.stderr
    assert len(calls) == 1 and "suites/conformance" in calls[0]


@pytest.mark.parametrize("family", ["typo", "drivers"])
def test_invalid_or_empty_driver_selection_fails_before_execution(family, cargo_stub):
    result, calls = run_harness(
        "docker",
        family,
        cargo_stub,
        OPENSHELL_E2E_DOCKER_FEATURES="",
    )
    assert result.returncode != 0
    assert not calls


def test_operator_workspace_conformance_exclusion_is_preserved(cargo_stub):
    result, calls = run_harness(
        "kubernetes",
        "all",
        cargo_stub,
        OPENSHELL_E2E_KUBERNETES_FEATURES="e2e-kubernetes-workspace-operator",
    )
    assert result.returncode == 0, result.stderr
    assert len(calls) == 1 and "suites/conformance" not in calls[0]


def test_runtime_profiles_preserve_existing_targets():
    # Frozen from the pre-migration branch workflow: conformance on every
    # runtime except operator mode; driver tests on external VM as well.
    core = {
        "docker-e2e",
        "podman-e2e",
        "vm-e2e",
        "kubernetes-v1.0.3-e2e",
        "kubernetes-v0.4.6-e2e",
        "kubernetes-workspace-managed-e2e",
        "vm-external-driver-e2e",
    }
    assert set(family_targets("conformance", "core")) == core | {
        "docker-external-driver-e2e",
        "podman-external-driver-e2e",
        "kubernetes-external-driver-e2e",
    }
    assert set(family_targets("drivers", "core")) == core | {
        "kubernetes-workspace-operator-e2e"
    }
    for family in ("conformance", "drivers"):
        assert set(family_targets(family, "release")) == {"docker-e2e", "vm-e2e"}
        assert family_targets(family, "gpu") == {"gpu-e2e"}
        assert family_targets(family, "kubernetes-ha") == {"kubernetes-ha-e2e"}
        assert family_targets(family, "kubernetes-credentials") == {
            "kubernetes-credentials-e2e"
        }


def test_docker_split_retains_all_six_legacy_suites():
    conformance = matrix_rows(workflow("e2e-conformance.yml")["jobs"]["docker"])[0]
    drivers = matrix_rows(workflow("e2e-drivers.yml")["jobs"]["docker"])[0]
    rows = drivers["suites"]
    # BaseLoader keeps YAML scalar values as strings; JSON suite defaults
    # contain native booleans. Compare the equivalent execution inputs.
    rows = [
        {
            key: value == "true" if key in ("python_proto", "mcp") else value
            for key, value in row.items()
        }
        for row in rows
    ]
    legacy = workflow("e2e-docker-test.yml")["on"]["workflow_call"]["inputs"][
        "suite-matrix"
    ]["default"]
    assert rows == json.loads(legacy)
    assert [row["suite"] for row in rows] == [
        "python",
        "oidc-python",
        "oidc-pkce-docker",
        "rust-docker",
        "oci-image",
        "mcp",
    ]
    assert [row["cmd"] for row in conformance["suites"]] == [
        "mise run --no-deps --skip-deps e2e:rust"
    ]


@pytest.mark.parametrize("family", ["conformance", "drivers"])
@pytest.mark.parametrize(
    "profile",
    ["core", "release", "gpu", "kubernetes-ha", "kubernetes-credentials", "typo"],
)
@pytest.mark.parametrize("status", ["success", "failure", "skipped", "cancelled", None])
def test_family_completion_requires_every_selected_job(family, profile, status):
    jobs = workflow(f"e2e-{family}.yml")["jobs"]
    result_job = jobs["result"]
    expected = [
        key
        for key in result_job["needs"]
        if profile in re.findall(r"inputs.profile == '([^']+)'", jobs[key]["if"])
    ]
    assert expected or profile == "typo"
    for selected in expected or ["unknown"]:
        results = {
            key: {"result": "success" if key in expected else "skipped"}
            for key in result_job["needs"]
        }
        if status is None:
            results.pop(selected, None)
        else:
            results[selected] = {"result": status}
        result = subprocess.run(
            ["bash", "-c", result_job["steps"][0]["run"]],
            env=os.environ | {"JOB_RESULTS": json.dumps(results), "PROFILE": profile},
            capture_output=True,
        )
        assert (result.returncode == 0) == (status == "success" and profile != "typo")


def test_families_call_driver_workflows_directly():
    assert not (WORKFLOWS / "e2e-runtime-tests.yml").exists()
    for family in ("conformance", "drivers"):
        jobs = workflow(f"e2e-{family}.yml")["jobs"]
        for driver in ("docker", "podman", "vm", "kubernetes", "gpu"):
            job = jobs[driver]
            suffix = "yaml" if driver == "gpu" else "yml"
            assert job["uses"] == f"./.github/workflows/e2e-{driver}-test.{suffix}"
            assert job["with"]["test-family"] == family
            if driver != "gpu":
                assert job["strategy"]["fail-fast"] == "false"


def test_existing_matrices_and_artifact_variants():
    conf = workflow("e2e-conformance.yml")["jobs"]["conformance-integration"]
    rows = json.loads(conf["with"]["test-matrix"])
    assert {(r["environment"], r["installer"]) for r in rows} == {
        ("ubuntu-docker-rootful", "deb"),
        ("ubuntu-k3s", "k3s"),
        ("ubuntu-k3s", "k3s-ha"),
        ("fedora-podman-rootful", "rpm"),
        ("fedora-podman-rootless", "rpm"),
    }
    features = workflow("e2e-features.yml")["jobs"]
    rows = [
        row
        for job in features.values()
        for row in json.loads(job["with"]["test-matrix"])
    ]
    assert len(rows) == 5
    assert (
        sorted(r["testsuite"] for r in rows)
        == ["oci-image"] * 3 + ["provider-refresh"] * 2
    )
    assert len({job["with"]["category"] for job in features.values()}) == 2
    drivers = workflow("e2e-drivers.yml")["jobs"]["driver-specific-integration"]
    rows = json.loads(drivers["with"]["test-matrix"])
    assert {(r["environment"], r["installer"], r["testsuite"]) for r in rows} == {
        ("fedora-podman-rootful", "binaries", "driver-podman"),
        ("fedora-podman-rootless", "binaries", "e2e-podman"),
        ("fedora-podman-rootless", "binaries", "driver-podman"),
    }
    runtime = workflow("e2e-conformance.yml")["jobs"]
    kube_rows = matrix_rows(runtime["kubernetes"])
    assert [(r["job-name"], r["agent-sandbox-version"]) for r in kube_rows[:2]] == [
        ("Kubernetes E2E (Rust smoke, Agent Sandbox v1beta1)", "v1.0.3"),
        ("Kubernetes E2E (Rust smoke, Agent Sandbox v1alpha1)", "v0.4.6"),
    ]
    for driver, arch in [
        ("docker", "aarch64"),
        ("podman", "x86_64"),
        ("kubernetes", "x86_64"),
        ("vm", "x86_64"),
    ]:
        for row in matrix_rows(runtime[driver]):
            artifact = row.get("gateway_artifact", row.get("gateway-artifact", ""))
            if artifact:
                assert artifact == f"openshell-gateway-plain-{arch}-unknown-linux-gnu"
                break
        else:
            pytest.fail(f"Missing external {driver} coverage")
    gpu = workflow("e2e-gpu-test.yaml")["jobs"]["e2e-gpu"]
    assert [
        (r["name"], r["experimental"]) for r in gpu["strategy"]["matrix"]["include"]
    ] == [
        ("linux-arm64", "false"),
        ("linux-amd64", "false"),
        ("wsl-amd64", "true"),
    ]


def test_release_and_required_gate_compatibility():
    branch = workflow("branch-e2e.yml")["jobs"]
    assert branch["core-e2e-result"]["name"] == "Core E2E result"
    assert branch["core-e2e-result"]["needs"] == [
        "pr_metadata",
        "conformance",
        "features",
        "drivers",
    ]
    assert branch["gpu-e2e-result"]["name"] == "GPU E2E result"
    for name in ("dev", "tag"):
        jobs = workflow(f"release-{name}.yml")["jobs"]
        for key, family in [
            ("conformance-integration", "conformance"),
            ("feature-specific-integration", "features"),
            ("driver-specific", "drivers"),
        ]:
            assert jobs[key]["uses"] == f"./.github/workflows/e2e-{family}.yml"
            assert jobs[key]["with"]["profile"] == "release"
