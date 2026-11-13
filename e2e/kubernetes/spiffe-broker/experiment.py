#!/usr/bin/env -S uv run --script
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Local Broker API spike against the existing pr-4732 SPIRE Helm dev cluster."""

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STATE = ROOT / ".cache/spiffe-broker"
NAMESPACE = "openshell-broker-probe"
BROKER = f"spiffe://openshell.local/ns/{NAMESPACE}/sa/broker-probe"
SUBJECT = "spiffe://openshell.local/openshell/gateway/broker-probe/sandbox/stable"
LABEL = {"openshell.ai/spiffe-broker-probe": "true"}
RESOURCE = "sandboxes.agents.x-k8s.io"


def kube(*args, value=None, raw=False):
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(ROOT / "kubeconfig"), *args],
        input=json.dumps(value).encode() if value is not None else None,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    return result.stdout if raw else result.stdout.decode()


def get(kind, name, namespace=None):
    return json.loads(
        kube(*(["-n", namespace] if namespace else []), "get", kind, name, "-o", "json")
    )


def apply(value):
    kube("apply", "-f", "-", value=value)


def manifest(kind, name, namespace=None, **extra):
    return {
        "apiVersion": "v1",
        "kind": kind,
        "metadata": {
            "name": name,
            "labels": LABEL,
            **({"namespace": namespace} if namespace else {}),
        },
        **extra,
    }


def rbac(kind, name, namespace=None, **extra):
    return {
        **manifest(kind, name, namespace, **extra),
        "apiVersion": "rbac.authorization.k8s.io/v1",
    }


def agent():
    items = json.loads(
        kube(
            "-n",
            "spire",
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/name=agent",
            "-o",
            "json",
        )
    )["items"]
    return next(
        p["metadata"]["name"] for p in items if p["status"].get("phase") == "Running"
    )


def setup():
    if not kube("config", "current-context").strip().startswith("k3d-"):
        raise RuntimeError("this experiment requires a local k3d context")
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    original = STATE / "agent-original.json"
    cm = get("configmap", "spire-agent", "spire")
    if not original.exists():
        original.write_text(json.dumps(cm))
    data = json.loads(cm["data"]["agent.conf"])
    data["agent"].setdefault("experimental", {})["broker"] = {
        "bind_address": "0.0.0.0:8443",
        "brokers": [
            {
                "broker": [
                    {
                        "id": BROKER,
                        "allowed_reference_types": [
                            {
                                "allowed_reference_types": {
                                    "type_url": "type.googleapis.com/spiffe.broker.KubernetesObjectReference",
                                    "allow_over_tcp": True,
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }
    for plugin in data["plugins"]["WorkloadAttestor"]:
        if "k8s" in plugin:
            plugin["k8s"]["plugin_data"]["experimental"] = {
                "broker": {
                    "access_policy": "enforced",
                    "brokers": [
                        {"broker": [{"id": BROKER, "pod_reference_scope": "cluster"}]}
                    ],
                }
            }
    kube(
        "-n",
        "spire",
        "patch",
        "configmap",
        "spire-agent",
        "--type=merge",
        "-p",
        json.dumps({"data": {"agent.conf": json.dumps(data)}}),
    )
    apply(
        rbac(
            "ClusterRole",
            "openshell-broker-probe-agent",
            rules=[
                {
                    "apiGroups": ["agents.x-k8s.io"],
                    "resources": ["sandboxes"],
                    "verbs": ["get", "list"],
                },
                {
                    "apiGroups": ["authorization.k8s.io"],
                    "resources": ["subjectaccessreviews"],
                    "verbs": ["create"],
                },
            ],
        )
    )
    apply(
        rbac(
            "ClusterRoleBinding",
            "openshell-broker-probe-agent",
            subjects=[
                {"kind": "ServiceAccount", "name": "spire-agent", "namespace": "spire"}
            ],
            roleRef={
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "openshell-broker-probe-agent",
            },
        )
    )
    if json.loads(cm["data"]["agent.conf"]) != data:
        kube("-n", "spire", "rollout", "restart", "daemonset/spire-agent")
    kube("-n", "spire", "rollout", "status", "daemonset/spire-agent", "--timeout=180s")
    namespace = manifest("Namespace", NAMESPACE)
    namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "restricted"
    apply(namespace)
    versions = get("crd", RESOURCE)["spec"]["versions"]
    sandbox_version = next(
        version["name"] for version in versions if version["storage"]
    )
    for name in ["allowed", "denied"]:
        apply(
            {
                **manifest("Sandbox", f"broker-probe-{name}", NAMESPACE),
                "apiVersion": f"agents.x-k8s.io/{sandbox_version}",
                "spec": {
                    **(
                        {"operatingMode": "Suspended"}
                        if sandbox_version == "v1beta1"
                        else {"replicas": 0}
                    ),
                    "podTemplate": {
                        "spec": {
                            "containers": [{"name": "unused", "image": "busybox:1.37"}]
                        }
                    },
                },
            }
        )
    apply(
        rbac(
            "Role",
            "broker-reference",
            NAMESPACE,
            rules=[
                {
                    "apiGroups": ["agents.x-k8s.io"],
                    "resources": ["sandboxes"],
                    "resourceNames": ["broker-probe-allowed"],
                    "verbs": ["impersonate-via-spire"],
                }
            ],
        )
    )
    apply(
        rbac(
            "RoleBinding",
            "broker-reference",
            NAMESPACE,
            subjects=[
                {
                    "kind": "User",
                    "name": BROKER,
                    "apiGroup": "rbac.authorization.k8s.io",
                }
            ],
            roleRef={
                "kind": "Role",
                "name": "broker-reference",
                "apiGroup": "rbac.authorization.k8s.io",
            },
        )
    )
    agents = json.loads(
        kube(
            "-n",
            "spire",
            "exec",
            "spire-server-0",
            "-c",
            "spire-server",
            "--",
            "/opt/spire/bin/spire-server",
            "agent",
            "list",
            "-output",
            "json",
        )
    )
    if len(agents["agents"]) != 1:
        raise RuntimeError("this fixture requires exactly one SPIRE agent")
    agent_id = agents["agents"][0]["id"]
    agent_id = f"spiffe://{agent_id['trust_domain']}{agent_id['path']}"
    (STATE / "agent-id").write_text(agent_id)
    # Read the class selected by this chart's controller manager.
    entries = json.loads(kube("get", "clusterspiffeids.spire.spiffe.io", "-o", "json"))[
        "items"
    ]
    class_name = entries[0]["spec"].get("className", "spire") if entries else "spire"
    target = get(RESOURCE, "broker-probe-allowed", NAMESPACE)
    apply(
        {
            "apiVersion": "spire.spiffe.io/v1alpha1",
            "kind": "ClusterStaticEntry",
            "metadata": {"name": "openshell-broker-probe", "labels": LABEL},
            "spec": {
                "className": class_name,
                "spiffeID": SUBJECT,
                "parentID": agent_id,
                "selectors": [
                    f"k8s:resource:{RESOURCE}",
                    f"k8s:uid:{target['metadata']['uid']}",
                ],
            },
        }
    )
    for name in ["broker-probe", "not-a-broker"]:
        apply(manifest("ServiceAccount", name, NAMESPACE))
        security = {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        }
        mounts = [{"name": "credentials", "mountPath": "/credentials"}]
        pod = manifest(
            "Pod",
            name,
            NAMESPACE,
            spec={
                "serviceAccountName": name,
                "restartPolicy": "OnFailure",
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "fsGroup": 1000,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "initContainers": [
                    {
                        "name": "fetch-identity",
                        "image": "ghcr.io/spiffe/spire-agent:1.15.3",
                        "command": [
                            "/opt/spire/bin/spire-agent",
                            "api",
                            "fetch",
                            "x509",
                            "-socketPath",
                            "/spiffe-workload-api/spire-agent.sock",
                            "-write",
                            "/credentials",
                        ],
                        "securityContext": security,
                        "volumeMounts": [
                            *mounts,
                            {
                                "name": "workload-api",
                                "mountPath": "/spiffe-workload-api",
                                "readOnly": True,
                            },
                        ],
                    }
                ],
                "containers": [
                    {
                        "name": "hold",
                        "image": "public.ecr.aws/docker/library/busybox:1.37.0",
                        "command": ["sleep", "86400"],
                        "securityContext": security,
                        "volumeMounts": mounts,
                    }
                ],
                "volumes": [
                    {"name": "credentials", "emptyDir": {}},
                    {
                        "name": "workload-api",
                        "csi": {"driver": "csi.spiffe.io", "readOnly": True},
                    },
                ],
            },
        )
        kube("-n", NAMESPACE, "delete", "pod", name, "--ignore-not-found")
        apply(pod)
        kube(
            "-n",
            NAMESPACE,
            "wait",
            "--for=condition=Ready",
            f"pod/{name}",
            "--timeout=180s",
        )
        directory = STATE / name
        directory.mkdir(exist_ok=True, mode=0o700)
        for filename in ["svid.0.pem", "svid.0.key", "bundle.0.pem"]:
            destination = directory / filename
            destination.write_bytes(
                kube(
                    "-n",
                    NAMESPACE,
                    "exec",
                    name,
                    "-c",
                    "hold",
                    "--",
                    "cat",
                    f"/credentials/{filename}",
                    raw=True,
                )
            )
            destination.chmod(0o600)
    print(
        "Prepared restricted client pods, exact-object RBAC, and UID-bound Sandbox registration."
    )


def test():
    target = get(RESOURCE, "broker-probe-allowed", NAMESPACE)
    environment = {
        **os.environ,
        "BROKER_ADDRESS": "127.0.0.1:18443",
        "BROKER_AGENT_ID": (STATE / "agent-id").read_text(),
        "BROKER_CREDENTIALS": str(STATE / "broker-probe"),
        "BROKER_RESOURCE": "sandboxes",
        "BROKER_GROUP": "agents.x-k8s.io",
        "BROKER_NAMESPACE": NAMESPACE,
        "BROKER_NAME": "broker-probe-allowed",
        "BROKER_UID": target["metadata"]["uid"],
        "BROKER_SANDBOX_ID": SUBJECT,
    }
    log = (STATE / "port-forward.log").open("wb")
    forward = subprocess.Popen(
        [
            "kubectl",
            "--kubeconfig",
            str(ROOT / "kubeconfig"),
            "-n",
            "spire",
            "port-forward",
            f"pod/{agent()}",
            "18443:8443",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            if "Forwarding from" in (STATE / "port-forward.log").read_text():
                break
            if forward.poll() is not None:
                raise RuntimeError("port-forward failed")
            time.sleep(0.2)
        binary = str(ROOT / "target/debug/examples/broker_probe")

        def run(title, overrides=None, connection_failure=None):
            result = subprocess.run(
                [binary],
                env={**environment, **(overrides or {})},
                capture_output=True,
                text=True,
            )
            if connection_failure:
                if result.returncode == 0 or connection_failure not in result.stderr:
                    raise RuntimeError(
                        f"{title}: expected TLS rejection ({connection_failure})"
                    )
                print(f"PASS: {title} rejected during TLS verification")
            else:
                if result.returncode:
                    raise RuntimeError(f"{title}: {result.stderr}")
                print(f"{title}: {result.stdout.strip()}")

        run("Sandbox identity")
        run("UID-only Sandbox reference", {"BROKER_UID_ONLY": "1"})
        run(
            "Untrusted agent certificate",
            {"BROKER_EMPTY_TRUST": "1"},
            connection_failure="UnknownIssuer",
        )
        run(
            "Missing required header",
            {"BROKER_OMIT_HEADER": "1", "BROKER_EXPECT_ERROR": "InvalidArgument"},
        )
        denied = get(RESOURCE, "broker-probe-denied", NAMESPACE)
        run(
            "Unauthorized object",
            {
                "BROKER_NAME": "broker-probe-denied",
                "BROKER_UID": denied["metadata"]["uid"],
                "BROKER_EXPECT_ERROR": "PermissionDenied",
            },
        )
        run(
            "Stale object UID",
            {"BROKER_UID": str(uuid.uuid4()), "BROKER_EXPECT_ERROR": "NotFound"},
        )
        run(
            "Unauthorized broker",
            {
                "BROKER_CREDENTIALS": str(STATE / "not-a-broker"),
                "BROKER_EXPECT_ERROR": "Unknown",
            },
        )
        run(
            "Wrong agent identity",
            {"BROKER_AGENT_ID": "spiffe://openshell.local/untrusted"},
            connection_failure="unexpected agent SPIFFE identity",
        )
    finally:
        forward.terminate()
        forward.wait(timeout=10)
        log.close()


def cleanup():
    original = STATE / "agent-original.json"
    if original.exists():
        kube(
            "-n",
            "spire",
            "patch",
            "configmap",
            "spire-agent",
            "--type=merge",
            "-p",
            json.dumps({"data": json.loads(original.read_text())["data"]}),
        )
        kube("-n", "spire", "rollout", "restart", "daemonset/spire-agent")
        kube(
            "-n",
            "spire",
            "rollout",
            "status",
            "daemonset/spire-agent",
            "--timeout=180s",
        )
    for resource in [
        "namespace",
        "clusterrole",
        "clusterrolebinding",
        "clusterstaticentry",
    ]:
        kube(
            "delete",
            resource,
            "-l",
            "openshell.ai/spiffe-broker-probe=true",
            "--ignore-not-found",
        )
    for directory in ["broker-probe", "not-a-broker"]:
        for path in (STATE / directory).glob("*"):
            path.unlink()
    original.unlink(missing_ok=True)
    print(
        "Restored SPIRE configuration and removed probe resources and exported credentials."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "test", "cleanup"])
    args = parser.parse_args()
    globals()[args.action]()
