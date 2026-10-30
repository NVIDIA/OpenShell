# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Deploy and verify an isolated listener release on the selected local/CI cluster."""

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--topology",
        choices=("shared", "dedicated"),
        default=os.getenv("OPENSHELL_E2E_APP_TOPOLOGY", "dedicated"),
    )
    parser.add_argument(
        "--delivery",
        choices=("push", "poll"),
        default=os.getenv("OPENSHELL_E2E_APP_DELIVERY", "push"),
    )
    parser.add_argument(
        "--takeover",
        choices=("graceful", "abrupt"),
        default=os.getenv("OPENSHELL_E2E_APP_TAKEOVER", "graceful"),
    )
    parser.add_argument("--image-tag", default=os.getenv("IMAGE_TAG", "dev"))
    parser.add_argument(
        "--registry", default=os.getenv("OPENSHELL_REGISTRY", "openshell")
    )
    args = parser.parse_args()
    namespace = "listener-e2e-" + uuid.uuid4().hex[:8]
    context = os.getenv("OPENSHELL_E2E_KUBE_CONTEXT")
    kubeconfig = os.getenv("OPENSHELL_E2E_KUBECONFIG")
    config_args = ["--kubeconfig", kubeconfig] if kubeconfig else []
    kube_args = [*config_args, *(["--context", context] if context else [])]
    helm_args = [*config_args, *(["--kube-context", context] if context else [])]
    k = ["kubectl", *kube_args, "-n", namespace]
    helm = ["helm", *helm_args]
    cli = Path(os.getenv("OPENSHELL_BIN", ROOT / "target/debug/openshell")).resolve()
    evidence = (
        ROOT
        / "results/app-listener"
        / f"{args.topology}-{args.delivery}-{args.takeover}"
    )
    evidence.mkdir(parents=True, exist_ok=True)

    def run(command, *, input=None, check=True, stdout=None, stderr=None):
        result = subprocess.run(
            command,
            input=input,
            text=True,
            check=False,
            stdout=stdout,
            stderr=stderr,
            timeout=600,
        )
        if check and result.returncode:
            raise RuntimeError(f"{command[:6]} exited {result.returncode}")
        return result

    def capture(command, destination):
        with (evidence / destination).open("w") as output:
            run(command, check=False, stdout=output)

    def wait_for_shared_hosts():
        if args.topology != "shared":
            return
        # TCP readiness precedes token projection and authenticated attachment.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            listing = subprocess.run(
                [
                    *k,
                    "get",
                    "pods",
                    "-l",
                    "app.kubernetes.io/component=supervisor",
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            members = (
                json.loads(listing.stdout)["items"] if listing.returncode == 0 else []
            )
            attached = 0
            for member in members:
                logs = subprocess.run(
                    [*k, "logs", member["metadata"]["name"], "-c", "supervisor"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                attached += "gateway accepted the supervisor host" in logs.stdout
            if len(members) == 2 and attached == 2:
                return
            time.sleep(2)
        raise AssertionError(
            "both supervisor hosts must authenticate before creating sandboxes"
        )

    if subprocess.run(
        ["kubectl", *kube_args, "get", "crd/sandboxes.agents.x-k8s.io"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    ).returncode:
        run(["bash", str(ROOT / "e2e/support/install-agent-sandbox.sh"), *kube_args])
    assert cli.is_file(), f"Build the CLI or set OPENSHELL_BIN: {cli}"
    run(["kubectl", *kube_args, "create", "namespace", namespace])
    try:
        with tempfile.TemporaryDirectory(prefix="openshell-listener-tls-") as temporary:
            material = Path(temporary)
            run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(material / "app.key"),
                    "-out",
                    str(material / "app.crt"),
                    "-days",
                    "2",
                    "-subj",
                    "/CN=*.services.example.com",
                    "-addext",
                    "subjectAltName=DNS:*.services.example.com",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (material / "app.key").chmod(0o600)
            run(
                [
                    *k,
                    "create",
                    "secret",
                    "tls",
                    "openshell-app-tls",
                    "--cert",
                    str(material / "app.crt"),
                    "--key",
                    str(material / "app.key"),
                ]
            )
            values = {
                "fullnameOverride": "listener-e2e",
                "global": {
                    "image": {
                        "registry": "",
                        "tag": args.image_tag,
                        "pullPolicy": "Never",
                    }
                },
                "gateway": {"image": {"repository": args.registry + "/gateway"}},
                "supervisor": {
                    "image": {"repository": args.registry + "/supervisor"},
                    "replicas": 2,
                    "recoveryTimeoutSeconds": 60,
                },
                "sandboxRuntime": {"image": {"repository": args.registry + "/sandbox"}},
                "sandbox": {
                    "image": {
                        "repository": "python",
                        "tag": "3.12-slim",
                        "pullPolicy": "IfNotPresent",
                    }
                },
                "server": {
                    "auth": {"allowUnauthenticatedUsers": True},
                    "tls": {"enableMtls": False},
                },
                "gatewayConfig": {
                    "openshell.gateway": {"config_delivery_mode": args.delivery},
                    "openshell.drivers.kubernetes": {"supervisor_topology": "gateway"}
                    if args.topology == "shared"
                    else {},
                    "openshell.supervisor.app_listener": {
                        "enabled": True,
                        "port": 9443,
                        "domain": "services.example.com",
                    },
                    "openshell.drivers.kubernetes.sandbox_runtime.app_listener": {
                        "tls_secret_name": "openshell-app-tls",
                    },
                },
            }
            value_file = material / "values.json"
            value_file.write_text(json.dumps(values))
            run(
                [
                    *helm,
                    "upgrade",
                    "--install",
                    "listener-e2e",
                    str(ROOT / "deploy/helm/openshell"),
                    "-n",
                    namespace,
                    "-f",
                    str(value_file),
                    "--wait",
                    "--timeout",
                    "5m",
                ]
            )
            wait_for_shared_hosts()
            # The port is used only for API forwarding; app clients run inside Pods.
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            env = dict(os.environ)
            if context or kubeconfig:
                env["KUBECONFIG"] = str(material / "kubeconfig")
                with Path(env["KUBECONFIG"]).open("w") as output:
                    run(
                        [
                            "kubectl",
                            *kube_args,
                            "config",
                            "view",
                            "--minify",
                            "--raw",
                            "--flatten",
                        ],
                        stdout=output,
                    )
            command = [
                sys.executable,
                str(HERE / "verify.py"),
                "--namespace",
                namespace,
                "--topology",
                args.topology,
                "--gateway-endpoint",
                f"https://localhost:{port}",
                "--forward-gateway",
                "service/listener-e2e",
                "--cli",
                str(cli),
                "--app-ca",
                str(material / "app.crt"),
                "--network-policy",
            ]
            if args.topology == "shared":
                command += ["--takeover", args.takeover]
            else:
                command += ["--expire-gateway", "statefulset/listener-e2e"]
            with (evidence / "enabled.log").open("w") as output:
                result = subprocess.run(
                    command,
                    env=env,
                    text=True,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                )
            print((evidence / "enabled.log").read_text(), flush=True)
            assert result.returncode == 0, "enabled-listener checks failed"
            disabled = material / "disabled.json"
            disabled.write_text(
                json.dumps(
                    {
                        "gatewayConfig": {
                            "openshell.supervisor.app_listener": {"enabled": False}
                        }
                    }
                )
            )
            run(
                [
                    *helm,
                    "upgrade",
                    "listener-e2e",
                    str(ROOT / "deploy/helm/openshell"),
                    "-n",
                    namespace,
                    "--reuse-values",
                    "-f",
                    str(disabled),
                    "--wait",
                    "--timeout",
                    "3m",
                ]
            )
            wait_for_shared_hosts()
            # A separate pass verifies actual disabled sockets and legacy ingress.
            disabled_command = [
                *command[: command.index("--network-policy")],
                "--disabled",
                "--gateway-service",
                "listener-e2e",
            ]
            with (evidence / "disabled.log").open("w") as output:
                result = subprocess.run(
                    disabled_command,
                    env=env,
                    text=True,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=300,
                )
            print((evidence / "disabled.log").read_text(), flush=True)
            assert result.returncode == 0, "disabled-listener checks failed"
    finally:
        capture(
            [*k, "get", "pods,services,endpointslices,networkpolicies", "-o", "wide"],
            "resources.log",
        )
        capture([*k, "get", "events", "--sort-by=.lastTimestamp"], "events.log")
        pods = subprocess.run(
            [*k, "get", "pods", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if pods.returncode == 0:
            for pod in json.loads(pods.stdout)["items"]:
                for container in pod["spec"]["containers"]:
                    if container["name"] in ("supervisor", "openshell-gateway"):
                        capture(
                            [
                                *k,
                                "logs",
                                pod["metadata"]["name"],
                                "-c",
                                container["name"],
                                "--tail=1000",
                            ],
                            pod["metadata"]["name"] + ".log",
                        )
        run(
            [
                *helm,
                "uninstall",
                "listener-e2e",
                "-n",
                namespace,
                "--wait",
                "--timeout",
                "2m",
            ],
            check=False,
        )
        run(
            ["kubectl", *kube_args, "delete", "namespace", namespace, "--wait=false"],
            check=False,
        )


if __name__ == "__main__":
    main()
