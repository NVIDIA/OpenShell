# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check installer/service combinations without requiring a Linux guest."""

from pathlib import Path

import pytest
import yaml
from ansible.template import Templar, trust_as_template

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "tests/ansible/roles"


def tasks(role, name="main.yaml"):
    return yaml.safe_load((ROLES / role / "tasks" / name).read_text())


def render(value, variables):
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    if isinstance(value, str):
        return Templar(variables=variables).template(trust_as_template(value))
    return value


@pytest.mark.parametrize("installer", ["binaries", "deb", "rpm"])
@pytest.mark.parametrize("rootless", [False, True])
def test_installed_gateway_service_context(installer, rootless):
    variables = {
        "openshell_gateway_user": "tmachine" if rootless else "root",
        "openshell_gateway_home": "/home/tmachine" if rootless else "/root",
        "openshell_gateway_uid": "1000" if rootless else "0",
    }
    packaged = installer != "binaries"
    if packaged:
        # Use the actual package registration inputs, including HTTPS.
        registration = tasks("openshell_packaged_gateway")[-1]
        variables.update(registration["vars"])
        assert variables["openshell_client_gateway_endpoint"].startswith("https://")
    context = render(
        tasks("openshell_client")[-1]["vars"]["openshell_test_gateway_context"],
        variables,
    )
    assert context["name"] == ("openshell" if packaged else "tmachine")
    assert context["config_path"] == (
        "/var/lib/openshell-qualification/gateway.toml"
        if packaged
        else "/etc/openshell/gateway.toml"
    )
    assert context["service_scope"] == ("user" if packaged else "system")
    assert context["service_user"] == ("tmachine" if packaged and rootless else "root")
    assert str(context["service_uid"]) == ("1000" if packaged and rootless else "0")
    assert context["network_name"] == ("openshell" if packaged else "tmachine")
    variables["openshell_test_gateway"] = context

    environment = render(
        tasks("openshell_test_gateway")[-1]["ansible.builtin.set_fact"][
            "openshell_test_gateway_service_environment"
        ],
        variables,
    )
    assert environment["HOME"] == (
        "/home/tmachine" if packaged and rootless else "/root"
    )
    assert environment["XDG_RUNTIME_DIR"] == f"/run/user/{context['service_uid']}"
    assert environment["DBUS_SESSION_BUS_ADDRESS"] == (
        f"unix:path=/run/user/{context['service_uid']}/bus"
    )

    restart = tasks("openshell_test_gateway", "restart.yaml")[0]["block"][0]
    assert render(restart["become_user"], variables) == context["service_user"]
    assert (
        render(restart["ansible.builtin.systemd_service"]["scope"], variables)
        == (context["service_scope"])
    )
    journal = render(
        tasks("openshell_test_gateway", "journal.yaml")[0]["ansible.builtin.command"][
            "argv"
        ],
        variables,
    )
    if packaged:
        assert "_SYSTEMD_USER_UNIT=openshell-gateway.service" in journal
        assert f"_UID={context['service_uid']}" in journal
        assert "--unit" not in journal
    else:
        assert journal[1:3] == ["--unit", "openshell-gateway.service"]


def test_missing_gateway_metadata_has_no_binary_fallback():
    metadata_task = tasks("openshell_test_gateway")[0]
    assert metadata_task["ansible.builtin.slurp"]["src"] == (
        "/var/lib/openshell-test/gateway.yaml"
    )
    assert "ignore_errors" not in metadata_task
    assert "failed_when" not in metadata_task


def test_fixture_targets_podman_table_in_active_config():
    play = yaml.safe_load(
        (
            ROOT / "tests/ansible/playbooks/drivers/podman/userns-profile.yaml"
        ).read_text()
    )[0]
    fixture = next(
        task["ansible.builtin.blockinfile"]
        for task in play["tasks"]
        if "ansible.builtin.blockinfile" in task
    )
    assert fixture["path"] == "{{ openshell_test_gateway.config_path }}"
    assert fixture["insertafter"] == r"^\[openshell\.drivers\.podman\]$"
