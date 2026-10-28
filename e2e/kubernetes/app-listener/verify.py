# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify an isolated Helm listener release, without discovery or a proxy.

Run with uv run --no-project python; see README.md for deployment prerequisites.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--gateway-endpoint", required=True)
    parser.add_argument(
        "--forward-gateway",
        help="Maintain an API port-forward to this Service across gateway restarts (e.g. service/listener-review)",
    )
    parser.add_argument("--app-ca", type=Path, required=True)
    parser.add_argument("--cli", default="target/debug/openshell")
    parser.add_argument("--domain", default="services.example.com")
    parser.add_argument("--port", default="9443")
    parser.add_argument(
        "--disabled",
        action="store_true",
        help="Check a disabled listener and continued gateway application ingress",
    )
    parser.add_argument(
        "--gateway-service", help="Gateway Service used by the disabled-listener check"
    )
    parser.add_argument(
        "--takeover",
        nargs="?",
        const="graceful",
        choices=("graceful", "abrupt"),
        help="Stop a shared owner Pod; abrupt requires Docker access to the k3d/kind node",
    )
    parser.add_argument(
        "--expire-gateway",
        help="Scale this isolated gateway workload to zero, verify expiry, then restore it (e.g. statefulset/listener-review)",
    )
    parser.add_argument(
        "--network-policy",
        action="store_true",
        help="Require denied-client enforcement",
    )
    args = parser.parse_args()
    if args.disabled and not args.gateway_service:
        parser.error("--disabled requires --gateway-service")
    prefix = "listener-" + uuid.uuid4().hex[:6]
    k = ["kubectl", "-n", args.namespace]
    cli = [
        str(Path(args.cli).resolve()),
        "--gateway-endpoint",
        args.gateway_endpoint,
        "--gateway-insecure",
    ]
    created = []

    def run(command, *, check=True, timeout=180, input=None):
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=timeout, input=input
        )
        if check and result.returncode:
            raise RuntimeError(f"{command[:7]}: {result.stdout}\n{result.stderr}")
        return result

    def apply(obj):
        run([*k, "apply", "-f", "-"], input=json.dumps(obj))

    def probe(mode, ip, host, *extra, client="allowed"):
        return run(
            [
                *k,
                "exec",
                prefix + "-" + client,
                "--",
                "python",
                "/test/client.py",
                mode,
                ip,
                args.port,
                host,
                *extra,
            ],
            timeout=60,
        )

    def hostname(name, service="web"):
        return (
            f"default--{name}" + (f"--{service}" if service else "") + "." + args.domain
        )

    def pods():
        items = json.loads(run([*k, "get", "pods", "-o", "json"]).stdout)["items"]
        return [
            pod
            for pod in items
            if pod["status"].get("podIP")
            and not pod["metadata"].get("deletionTimestamp")
            and any(c["name"] == "supervisor" for c in pod["spec"]["containers"])
        ]

    def owner(name, timeout=120):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            matches = []
            for pod in pods():
                ip = pod["status"]["podIP"]
                result = run(
                    [
                        *k,
                        "exec",
                        prefix + "-allowed",
                        "--",
                        "python",
                        "/test/client.py",
                        "http",
                        ip,
                        args.port,
                        hostname(name),
                    ],
                    check=False,
                    timeout=20,
                )
                if result.returncode == 0:
                    status, body = json.loads(result.stdout)
                    if status == 200:
                        matches.append((pod, body))
            if len(matches) == 1:
                return matches[0]
            assert len(matches) < 2, "multiple supervisors serve one sandbox"
            time.sleep(1)
        raise AssertionError(f"no unique serving owner for {name}")

    def create(index, wait=True):
        name = f"{prefix}-{index}"
        created.append(name)
        run(
            [
                *cli,
                "sandbox",
                "create",
                "--name",
                name,
                "--from",
                "python:3.12-slim",
                "--detach",
                "--expose",
                "8080",
                "--",
                "python",
                "-c",
                (HERE / "app.py").read_text(),
            ]
        )
        run([*cli, "service", "expose", name, "8080", "web"])
        return (name, *owner(name)) if wait else name

    def check_disabled():
        name = create(0, wait=False)
        deadline = time.monotonic() + 120
        while True:
            members = pods()
            if members and all(p["status"].get("phase") == "Running" for p in members):
                break
            assert time.monotonic() < deadline, "disabled supervisor did not start"
            time.sleep(1)
        for member in members:
            container = next(
                c for c in member["spec"]["containers"] if c["name"] == "supervisor"
            )
            assert not any(p.get("name") == "app" for p in container.get("ports", []))
            assert not any(
                v["name"] == "app-tls" for v in container.get("volumeMounts", [])
            )
            assert not any(
                e["name"] == "OPENSHELL_APP_LISTENER_ENABLED"
                and e.get("value") == "true"
                for e in container.get("env", [])
            )
            print(
                probe(
                    "disabled", member["status"]["podIP"], hostname(name), client="host"
                ).stdout,
                end="",
                flush=True,
            )
        services = json.loads(
            run(
                [
                    *k,
                    "get",
                    "services",
                    "-l",
                    "openshell.ai/component=app-service",
                    "-o",
                    "json",
                ]
            ).stdout
        )
        assert not services["items"], "disabled deployment created app Services"
        gateway = json.loads(
            run([*k, "get", "service", args.gateway_service, "-o", "json"]).stdout
        )
        deadline = time.monotonic() + 120
        while True:
            result = run(
                [
                    *k,
                    "exec",
                    prefix + "-host",
                    "--",
                    "python",
                    "/test/client.py",
                    "gateway",
                    gateway["spec"]["clusterIP"],
                    "8080",
                    f"default--{name}--web.openshell.localhost",
                ],
                check=False,
            )
            if result.returncode == 0:
                print(result.stdout, end="", flush=True)
                break
            assert time.monotonic() < deadline, result.stderr
            time.sleep(1)
        print(
            "PASS disabled listener omits TLS material/port and preserves gateway access",
            flush=True,
        )

    def identity(name):
        obj = json.loads(
            run([*k, "get", "sandbox", "default--" + name, "-o", "json"]).stdout
        )
        pod = json.loads(
            run([*k, "get", "pod", "default--" + name, "-o", "json"]).stdout
        )
        return (
            obj["metadata"]["uid"],
            pod["metadata"]["uid"],
            obj["metadata"]["annotations"]["openshell.ai/sandbox-runtime-generation"],
        )

    def stop_owner(pod):
        name = pod["metadata"]["name"]
        if args.takeover == "abrupt":
            container = next(
                c["containerID"].split("://", 1)[1]
                for c in pod["status"]["containerStatuses"]
                if c["name"] == "supervisor"
            )
            for ctr in (["ctr"], ["k3s", "ctr"]):
                result = run(
                    [
                        "docker",
                        "exec",
                        pod["spec"]["nodeName"],
                        *ctr,
                        "-n",
                        "k8s.io",
                        "tasks",
                        "kill",
                        "--signal",
                        "SIGKILL",
                        container,
                    ],
                    check=False,
                )
                if result.returncode == 0:
                    break
            assert result.returncode == 0, result.stderr
            run(
                [
                    *k,
                    "delete",
                    "pod",
                    name,
                    "--grace-period=0",
                    "--force",
                    "--wait=false",
                ]
            )
        else:
            run([*k, "delete", "pod", name, "--wait=false"])

    def streams(mode, ip, first, second_ip, second, action):
        process = subprocess.Popen(
            [
                *k,
                "exec",
                prefix + "-allowed",
                "--",
                "python",
                "-u",
                "/test/client.py",
                mode,
                ip,
                args.port,
                first,
                second_ip,
                args.port,
                second,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            # Bound output waits too: a stalled kubectl exec must not hang the suite.
            import selectors

            ready = False
            end = time.monotonic() + 110
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while process.poll() is None and time.monotonic() < end:
                    if not selector.select(timeout=1):
                        continue
                    line = process.stdout.readline()
                    print(line, end="", flush=True)
                    if line.startswith("READY:"):
                        ready = True
                        action()
            tail, _ = process.communicate(timeout=5)
            print(tail, end="", flush=True)
            assert ready and process.returncode == 0, (
                f"{mode}: exit={process.returncode}"
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    with (
        tempfile.TemporaryDirectory(prefix="openshell-listener-client-") as config,
        ExitStack() as stack,
    ):
        # Never change or depend on the developer's selected gateway/login.
        previous = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = config
        if args.forward_gateway:
            endpoint = urlsplit(args.gateway_endpoint)
            assert (
                endpoint.hostname in ("localhost", "127.0.0.1", "::1") and endpoint.port
            )
            stopped = threading.Event()

            def forward():
                with (Path(config) / "forward.log").open("w") as log:
                    while not stopped.is_set():
                        with subprocess.Popen(
                            [
                                *k,
                                "port-forward",
                                args.forward_gateway,
                                f"{endpoint.port}:8080",
                            ],
                            stdout=log,
                            stderr=subprocess.STDOUT,
                        ) as child:
                            while child.poll() is None and not stopped.wait(0.2):
                                pass
                            if child.poll() is None:
                                child.terminate()
                            try:
                                child.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                child.kill()
                                child.wait()
                        stopped.wait(1)

            forwarding = threading.Thread(target=forward)
            forwarding.start()

            def stop_forward():
                stopped.set()
                forwarding.join(timeout=10)
                assert not forwarding.is_alive(), "API port-forward did not stop"

            stack.callback(stop_forward)
        try:
            deadline = time.monotonic() + 30
            while True:
                ready = run([*cli, "sandbox", "list"], check=False, timeout=15)
                if ready.returncode == 0:
                    break
                assert time.monotonic() < deadline, ready.stderr
                time.sleep(1)
            apply(
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": prefix, "labels": {"listener-e2e": prefix}},
                    "data": {
                        "ca.crt": args.app_ca.read_text(),
                        "client.py": (HERE / "client.py").read_text(),
                    },
                }
            )
            for role in ("host",) if args.disabled else ("allowed", "denied"):
                apply(
                    {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": prefix + "-" + role,
                            "labels": {"listener-e2e": prefix, "listener-client": role},
                        },
                        "spec": {
                            "hostNetwork": role == "host",
                            "dnsPolicy": "ClusterFirstWithHostNet"
                            if role == "host"
                            else "ClusterFirst",
                            "containers": [
                                {
                                    "name": "client",
                                    "image": "python:3.12-slim",
                                    "command": ["sleep", "infinity"],
                                    "volumeMounts": [
                                        {
                                            "name": "test",
                                            "mountPath": "/test",
                                            "readOnly": True,
                                        }
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "test", "configMap": {"name": prefix}}
                            ],
                        },
                    }
                )
            for index, labels in enumerate(
                (
                    {"app.kubernetes.io/component": "supervisor"},
                    {"openshell.ai/component": "supervisor"},
                )
            ):
                apply(
                    {
                        "apiVersion": "networking.k8s.io/v1",
                        "kind": "NetworkPolicy",
                        "metadata": {
                            "name": prefix + str(index),
                            "labels": {"listener-e2e": prefix},
                        },
                        "spec": {
                            "podSelector": {"matchLabels": labels},
                            "policyTypes": ["Ingress"],
                            "ingress": [
                                {
                                    "from": [
                                        {
                                            "podSelector": {
                                                "matchLabels": {
                                                    "listener-e2e": prefix,
                                                    "listener-client": "allowed",
                                                }
                                            }
                                        }
                                    ],
                                    "ports": [
                                        {"protocol": "TCP", "port": int(args.port)}
                                    ],
                                }
                            ],
                        },
                    }
                )
            run(
                [
                    *k,
                    "wait",
                    "pod",
                    "-l",
                    "listener-e2e=" + prefix,
                    "--for=condition=Ready",
                    "--timeout=120s",
                ]
            )
            if args.disabled:
                check_disabled()
                return
            name, pod, body = create(0)
            ip = pod["status"]["podIP"]
            host = hostname(name)
            print("PASS unique serving supervisor and named HTTP route", flush=True)
            services = json.loads(run([*k, "get", "services", "-o", "json"]).stdout)
            assert not any(
                service["metadata"]["name"].startswith("os-app-")
                or service["metadata"].get("labels", {}).get("openshell.ai/component")
                == "app-service"
                for service in services["items"]
            ), "listener deployment created app Services"
            print("PASS Pod-IP ingress without per-sandbox app Services", flush=True)
            assert json.loads(probe("http", ip, hostname(name, "")).stdout)[0] == 200
            print("PASS unnamed HTTP route", flush=True)
            print(probe("headers", ip, host).stdout, end="", flush=True)
            print(
                probe("reject", ip, hostname(name, "missing")).stdout,
                end="",
                flush=True,
            )
            if args.network_policy:
                print(
                    probe("blocked", ip, host, client="denied").stdout,
                    end="",
                    flush=True,
                )
            run(
                [
                    *cli,
                    "service",
                    "expose",
                    name,
                    "8080",
                    "token",
                    "--authorization-mode",
                    "bearer-passthrough",
                ]
            )
            deadline = time.monotonic() + 30
            while True:
                result = run(
                    [
                        *k,
                        "exec",
                        prefix + "-allowed",
                        "--",
                        "python",
                        "/test/client.py",
                        "bearer",
                        ip,
                        args.port,
                        hostname(name, "token"),
                    ],
                    check=False,
                )
                if result.returncode == 0:
                    print(result.stdout, end="", flush=True)
                    break
                assert time.monotonic() < deadline, result.stderr
                time.sleep(1)
            streams(
                "withdraw",
                ip,
                host,
                ip,
                hostname(name, ""),
                lambda: run([*cli, "service", "delete", name, "web"]),
            )
            print(probe("reject", ip, host).stdout, end="", flush=True)
            run([*cli, "service", "expose", name, "8080", "web"])
            _, current = owner(name)
            assert current["boot"] == body["boot"] and current["pid"] == body["pid"]
            print("PASS re-exposure preserves running application", flush=True)
            if args.takeover:
                peer = None
                for index in range(1, 33):
                    candidate = create(index)
                    if candidate[1]["metadata"]["name"] != pod["metadata"]["name"]:
                        peer = candidate
                        break
                assert peer is not None, (
                    "could not place a sandbox on another supervisor"
                )
                other, other_pod, other_body = peer
                before = identity(name)
                streams(
                    "takeover",
                    ip,
                    host,
                    other_pod["status"]["podIP"],
                    hostname(other),
                    lambda: stop_owner(pod),
                )
                new_pod, after = owner(name, timeout=180)
                assert new_pod["metadata"]["uid"] != pod["metadata"]["uid"]
                assert identity(name) == before
                assert (after["boot"], after["pid"]) == (body["boot"], body["pid"])
                assert after["counter"] > body["counter"]
                peer_pod, peer_after = owner(other)
                assert peer_pod["metadata"]["uid"] == other_pod["metadata"]["uid"]
                assert peer_after["boot"] == other_body["boot"]
                print(
                    f"PASS {args.takeover} owner takeover preserves workload Pod, generation, process and memory; peer unaffected",
                    flush=True,
                )
            if args.expire_gateway:
                obj = json.loads(
                    run([*k, "get", args.expire_gateway, "-o", "json"]).stdout
                )
                replicas = obj["spec"]["replicas"]
                assert replicas > 0
                expiry_pod, _ = owner(name)
                expiry_ip = expiry_pod["status"]["podIP"]
                try:
                    streams(
                        "expire",
                        expiry_ip,
                        host,
                        expiry_ip,
                        hostname(name, ""),
                        lambda: run([*k, "scale", args.expire_gateway, "--replicas=0"]),
                    )
                    print(probe("reject", expiry_ip, host).stdout, end="", flush=True)
                finally:
                    run([*k, "scale", args.expire_gateway, f"--replicas={replicas}"])
                    run(
                        [*k, "rollout", "status", args.expire_gateway, "--timeout=180s"]
                    )
                _, resumed = owner(name)
                assert (resumed["boot"], resumed["pid"]) == (body["boot"], body["pid"])
                print(
                    "PASS gateway outage expires streams and routes; recovery preserves application",
                    flush=True,
                )
            print("PASS listener Kubernetes e2e", flush=True)
        finally:
            primary_failure = sys.exc_info()[0] is not None
            cleanup_failures = []
            for name in reversed(created):
                deadline = time.monotonic() + 60
                while True:
                    try:
                        deleted = run(
                            [*cli, "sandbox", "delete", name], check=False, timeout=10
                        )
                        if (
                            deleted.returncode == 0
                            or "not found" in (deleted.stdout + deleted.stderr).lower()
                        ):
                            break
                        detail = deleted.stderr
                    except subprocess.TimeoutExpired:
                        detail = "API request timed out during reconnection"
                    if time.monotonic() >= deadline:
                        cleanup_failures.append(name)
                        print(
                            f"Failed to clean sandbox {name}: {detail}",
                            file=sys.stderr,
                        )
                        break
                    time.sleep(1)
            run(
                [
                    *k,
                    "delete",
                    "pod,configmap,networkpolicy",
                    "-l",
                    "listener-e2e=" + prefix,
                    "--wait=false",
                ],
                check=False,
            )
            if previous is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = previous
            if cleanup_failures and not primary_failure:
                raise AssertionError(f"sandbox cleanup failed: {cleanup_failures}")


if __name__ == "__main__":
    main()
