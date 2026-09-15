# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Launch one Jupyter sandbox and submit code to its exposed kernel."""

from __future__ import annotations

import secrets
from pathlib import Path

from jupyter_sandbox import JupyterSandbox

from openshell import SandboxClient

EXAMPLE_DIR = Path(__file__).resolve().parent

# Configure the sandbox and the work submitted to its Jupyter kernel here.
IMAGE = "openshell-jupyter-sandbox:local"
POLICY = EXAMPLE_DIR / "policy.yaml"
NAME_PREFIX = "jupyter"
CODE = "print(sum(i * i for i in range(10)))"
GATEWAY: str | None = None  # None selects the active OpenShell gateway.
OPENSHELL_BIN = "openshell"  # Used only for service APIs missing from the SDK.


def main() -> None:
    with SandboxClient.from_active_cluster(cluster=GATEWAY) as client:
        health = client.health()
        print(f"Connected to OpenShell {health.version}")

        sandbox_name = f"{NAME_PREFIX}-{secrets.token_hex(3)}"
        with JupyterSandbox(
            client=client,
            name=sandbox_name,
            image=IMAGE,
            policy=POLICY,
            openshell_bin=OPENSHELL_BIN,
            cluster=GATEWAY,
        ) as sandbox:
            print(f"\nStarted sandbox {sandbox.name}")
            print(f"Jupyter service: {sandbox.service_url}")

            print("\nCreating a kernel and submitting code through the service:")
            print(CODE)
            result = sandbox.execute(CODE)
            print("\nResult:")
            print(result, end="" if result.endswith("\n") else "\n")


if __name__ == "__main__":
    main()
