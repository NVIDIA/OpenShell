# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Launch a fleet of Jupyter sandboxes and submit code to the first member."""

from __future__ import annotations

import secrets
from pathlib import Path

from fleet import Fleet
from jupyter_sandbox import JupyterSandbox

from openshell import SandboxClient

EXAMPLE_DIR = Path(__file__).resolve().parent

# Configure the fleet here.
IMAGE = "openshell-jupyter-sandbox:local"
SANDBOX_COUNT = 3
POLICY = EXAMPLE_DIR / "policy.yaml"
NAME_PREFIX = "jupyter"
CODE = "print(sum(i * i for i in range(10)))"
GATEWAY: str | None = None  # None selects the active OpenShell gateway.
OPENSHELL_BIN = "openshell"  # Used only for service APIs missing from the SDK.


def main() -> None:
    with SandboxClient.from_active_cluster(cluster=GATEWAY) as client:
        health = client.health()
        print(f"Connected to OpenShell {health.version}")

        run_id = secrets.token_hex(3)
        with Fleet(
            count=SANDBOX_COUNT,
            factory=lambda index: JupyterSandbox(
                client=client,
                name=f"{NAME_PREFIX}-{run_id}-{index + 1}",
                image=IMAGE,
                policy=POLICY,
                openshell_bin=OPENSHELL_BIN,
                cluster=GATEWAY,
            ),
        ) as fleet:
            print(f"\nStarted {len(fleet)} Jupyter sandboxes:")
            for sandbox in fleet:
                print(f"  {sandbox.name}: {sandbox.service_url}")

            print(f"\nSubmitting code to {fleet[0].name} over the Jupyter API:")
            print(CODE)
            result = fleet[0].execute(CODE)
            print("\nResult:")
            print(result, end="" if result.endswith("\n") else "\n")


if __name__ == "__main__":
    main()
