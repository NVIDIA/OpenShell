# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Create an OpenShell sandbox with Kata Containers runtime class.

The CLI does not yet expose a --runtime-class flag, but the gRPC API fully
supports it.  This script uses the Python SDK to set runtime_class_name on
the SandboxTemplate at creation time.

Usage:
    uv run examples/kata-containers/create-kata-sandbox.py \\
        --name my-agent \\
        --image myregistry.com/agent-sandbox:latest \\
        --runtime-class kata-containers \\
        --provider claude

Requirements:
    pip install openshell   # or: uv pip install openshell
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an OpenShell sandbox with a Kata Containers runtime class.",
    )
    parser.add_argument("--name", required=True, help="Sandbox name")
    parser.add_argument(
        "--image",
        default="ghcr.io/nvidia/openshell-community/sandboxes/base:latest",
        help="Container image for the sandbox",
    )
    parser.add_argument(
        "--runtime-class",
        default="kata-containers",
        help="Kubernetes RuntimeClass name (default: kata-containers)",
    )
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        help="Provider name to attach (repeatable)",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Gateway gRPC endpoint (auto-detected from active cluster if omitted)",
    )
    args = parser.parse_args()

    try:
        from openshell._proto import openshell_pb2, openshell_pb2_grpc
    except ImportError:
        print(
            "error: openshell package not installed. "
            "Run: uv pip install openshell",
            file=sys.stderr,
        )
        return 1

    from openshell import SandboxClient

    if args.endpoint:
        client = SandboxClient(args.endpoint)
    else:
        client = SandboxClient.from_active_cluster()

    template = openshell_pb2.SandboxTemplate(
        image=args.image,
        runtime_class_name=args.runtime_class,
    )

    request = openshell_pb2.CreateSandboxRequest(
        name=args.name,
        providers=args.provider,
        template=template,
    )

    print(f"Creating sandbox '{args.name}' with runtime class '{args.runtime_class}'...")
    response = client.stub.CreateSandbox(request)
    print(f"Sandbox created: {response.name} (id: {response.id})")
    print()
    print("Connect with:")
    print(f"    openshell sandbox connect {args.name}")
    print()
    print("Verify Kata isolation:")
    print(f"    openshell sandbox exec {args.name} -- uname -r")
    print(
        f"    kubectl -n openshell get pods -l sandbox={args.name}"
        " -o jsonpath='{.items[0].spec.runtimeClassName}'"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
