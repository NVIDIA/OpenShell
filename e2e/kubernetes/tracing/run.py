# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify gateway and Kubernetes compute-driver traces at a real OTLP collector."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager, nullcontext, suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib:0.164.0"
WORKLOAD_IMAGE = (
    "ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim"
    "@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3"
)
GATEWAY_SERVICE = "openshell-e2e-gateway"
GATEWAY_CREATE = "openshell.v1.OpenShell/CreateSandbox"
DRIVER_VALIDATE = "openshell.compute.v1.ComputeDriver/ValidateSandboxCreate"
DRIVER_CREATE = "openshell.compute.v1.ComputeDriver/CreateSandbox"


def stop_process_group(process, grace):
    """Give the owned harness time to tear down, then stop remaining children."""
    deadline = time.monotonic() + grace
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
        # The shell may exit before its probe finishes cleanup. Keep that
        # cleanup within the same grace period, even after reaping the shell.
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        pass
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run(
    command,
    *,
    timeout=60,
    check=True,
    log_path=None,
    termination_grace=10,
    own_group=True,
    **kwargs,
):
    input_text = kwargs.pop("input", None)
    output = log_path.open("w", buffering=1) if log_path else nullcontext(None)
    with output as log:
        process = subprocess.Popen(
            command,
            text=True,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=log if log else subprocess.PIPE,
            stderr=subprocess.STDOUT if log else subprocess.PIPE,
            start_new_session=own_group,
            **kwargs,
        )
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except BaseException:
            if own_group:
                stop_process_group(process, termination_grace)
            else:
                # Only the outer harness owns this group. A command's timeout
                # must not terminate the probe or its teardown.
                process.terminate()
                try:
                    process.wait(timeout=termination_grace)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.communicate(timeout=5)
            raise
        if own_group:
            # A shell can finish while background commands still own sockets.
            # Reclaim those descendants on successful and failing exits too.
            stop_process_group(process, termination_grace)
        result = subprocess.CompletedProcess(
            command, process.returncode, stdout or "", stderr or ""
        )
    if check and result.returncode:
        raise RuntimeError(
            f"{command[0]} exited {result.returncode}:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


@contextmanager
def termination_signals():
    """Turn handled cancellation into unwinding, including collector teardown."""
    signals = (signal.SIGINT, signal.SIGTERM)
    previous = {number: signal.getsignal(number) for number in signals}

    def interrupted(number, _frame):
        # A second normal cancellation must not interrupt bounded cleanup.
        for signum in signals:
            signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + number)

    for number in signals:
        signal.signal(number, interrupted)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def capture(command, destination, *, own_group=True):
    """Preserve diagnostics even when a failing cluster cannot answer."""
    try:
        result = run(command, check=False, own_group=own_group)
        destination.write_text(result.stdout + result.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        destination.write_text(f"Diagnostic capture failed: {error}\n")


def attributes(items):
    result = {}
    for item in items:
        key = item["key"]
        if key in result:
            raise ValueError(f"duplicate resource attribute {key}")
        result[key] = item.get("value", {}).get("stringValue")
    return result


def received_spans(logs):
    """Read OTLP JSON batches, ignoring the collector's own diagnostic records."""
    spans = []
    for line in logs.splitlines():
        try:
            batch = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(batch, dict) or "resourceSpans" not in batch:
            continue
        for resource in batch["resourceSpans"]:
            attrs = attributes(resource.get("resource", {}).get("attributes", []))
            for scope in resource.get("scopeSpans", []):
                spans.extend((span, attrs) for span in scope.get("spans", []))
    return spans


def valid_id(value, digits):
    return (
        isinstance(value, str)
        and re.fullmatch(rf"[0-9a-fA-F]{{{digits}}}", value) is not None
        and int(value, 16) != 0
    )


def witnesses(logs, gateway_name):
    """Require correctly attributed successful operations, not arbitrary traffic."""
    expected = {
        "gateway": (GATEWAY_SERVICE, GATEWAY_CREATE),
        "driver_validation": ("openshell-driver-kubernetes", DRIVER_VALIDATE),
        "driver_create": ("openshell-driver-kubernetes", DRIVER_CREATE),
    }
    found = {key: [] for key in expected}
    for span, resource in received_spans(logs):
        for role, (service, operation) in expected.items():
            if (
                resource.get("service.name") != service
                or span.get("name") != operation
                or resource.get("openshell.gateway.name") != gateway_name
                or resource.get("openshell.gateway.compute_driver") != "kubernetes"
                or not resource.get("service.version")
                or not valid_id(span.get("traceId"), 32)
                or not valid_id(span.get("spanId"), 16)
                or span.get("status", {}).get("code", 0) not in (0, 1)
            ):
                continue
            found[role].append(
                {
                    "trace_id": span["traceId"].lower(),
                    "span_id": span["spanId"].lower(),
                    "parent_span_id": span.get("parentSpanId", "").lower(),
                    "operation": operation,
                    "resource": resource,
                }
            )
    if not all(found.values()):
        missing = ", ".join(key for key, value in found.items() if not value)
        raise ValueError(f"collector missing expected spans/resources: {missing}")
    # Validation is a synchronous part of this public CreateSandbox request.
    # Actual provisioning may continue asynchronously and need not share that root.
    for gateway in found["gateway"]:
        for driver in found["driver_validation"]:
            if gateway["trace_id"] == driver["trace_id"]:
                return {
                    "gateway": gateway,
                    "driver_validation": driver,
                    "driver_create": found["driver_create"][0],
                }
    raise ValueError("gateway CreateSandbox and driver validation have no shared trace")


def wait_for_witnesses(read_logs, gateway_name, timeout=60):
    deadline = time.monotonic() + timeout
    last_error = "collector has not been read"
    while True:
        try:
            return witnesses(read_logs(), gateway_name)
        except ValueError as error:
            last_error = str(error)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"trace receipt deadline exceeded: {last_error}")
        time.sleep(1)


def confirm_receipt(evidence, gateway_name):
    # A shell EXIT trap can return zero even if the probe was never reached.
    # Require the child's receipt and independently recheck the captured data.
    try:
        receipt = json.loads((evidence / "receipt.json").read_text())
        received = witnesses((evidence / "collector.log").read_text(), gateway_name)
    except (OSError, ValueError) as error:
        raise RuntimeError(f"missing or invalid collector receipt: {error}") from error
    if receipt != received:
        raise RuntimeError("collector receipt does not match the captured spans")


def collector_manifest(namespace):
    config = {
        "receivers": {"otlp": {"protocols": {"grpc": {"endpoint": "0.0.0.0:4317"}}}},
        "exporters": {
            "file": {"path": "/dev/stdout", "format": "json", "flush_interval": "1s"}
        },
        "service": {
            "pipelines": {"traces": {"receivers": ["otlp"], "exporters": ["file"]}}
        },
    }
    metadata = {"name": "collector", "namespace": namespace}
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": metadata,
                "data": {"collector.json": json.dumps(config)},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": metadata,
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": "trace-receipt-collector"}},
                    "template": {
                        "metadata": {"labels": {"app": "trace-receipt-collector"}},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "containers": [
                                {
                                    "name": "collector",
                                    "image": COLLECTOR_IMAGE,
                                    "args": ["--config=/etc/collector/collector.json"],
                                    "ports": [{"name": "otlp", "containerPort": 4317}],
                                    "readinessProbe": {"tcpSocket": {"port": "otlp"}},
                                    "resources": {
                                        "requests": {"cpu": "100m", "memory": "64Mi"},
                                        "limits": {"cpu": "500m", "memory": "256Mi"},
                                    },
                                    # Reopening /dev/stdout needs access to the runtime's
                                    # pipe. This disposable fixture has no token or caps.
                                    "securityContext": {
                                        "runAsUser": 0,
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "volumeMounts": [
                                        {
                                            "name": "config",
                                            "mountPath": "/etc/collector",
                                            "readOnly": True,
                                        }
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "config", "configMap": {"name": "collector"}}
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": metadata,
                "spec": {
                    "selector": {"app": "trace-receipt-collector"},
                    "ports": [{"name": "otlp", "port": 4317, "targetPort": "otlp"}],
                },
            },
        ],
    }


def gateway_values(namespace, gateway_name):
    return {
        "server": {
            "name": gateway_name,
            "otlp": {
                "endpoint": f"http://collector.{namespace}.svc.cluster.local:4317",
                "serviceName": GATEWAY_SERVICE,
            },
            "extraEnv": [{"name": "OTEL_TRACES_SAMPLER", "value": "always_on"}],
        }
    }


def kubectl(namespace):
    context = os.environ.get("OPENSHELL_E2E_KUBE_CONTEXT")
    if not context:
        raise RuntimeError(
            "set OPENSHELL_E2E_KUBE_CONTEXT to a disposable test cluster"
        )
    command = ["kubectl", "--context", context]
    return [*command, "-n", namespace]


def check_receipt(evidence, namespace, gateway_name, cli):
    k = kubectl(namespace)
    name = "trace-" + uuid.uuid4().hex[:12]

    def read_logs():
        logs = run(
            [*k, "logs", "deployment/collector", "-c", "collector"], own_group=False
        ).stdout
        (evidence / "collector.log").write_text(logs)
        return logs

    try:
        create = run(
            [
                cli,
                "sandbox",
                "create",
                "--detach",
                "--name",
                name,
                "--from",
                WORKLOAD_IMAGE,
            ],
            timeout=360,
            own_group=False,
        )
        (evidence / "create.log").write_text(create.stdout + create.stderr)
        executed = run(
            [cli, "sandbox", "exec", name, "--", "sh", "-c", "printf collector-probe"],
            timeout=360,
            own_group=False,
        )
        if "collector-probe" not in executed.stdout:
            raise RuntimeError("sandbox probe did not execute successfully")
        receipt = wait_for_witnesses(read_logs, gateway_name)
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(
            "Collector received gateway and Kubernetes driver spans with resource attribution."
        )
    finally:
        deleted = run(
            [cli, "sandbox", "delete", name], timeout=120, check=False, own_group=False
        )
        (evidence / "delete.log").write_text(deleted.stdout + deleted.stderr)
        capture(
            [
                *kubectl(os.environ["OPENSHELL_E2E_KUBE_NAMESPACE"]),
                "get",
                "pods",
                "-o",
                "json",
            ],
            evidence / "gateway-pods.json",
            own_group=False,
        )
        capture(
            [*k, "logs", "deployment/collector", "-c", "collector"],
            evidence / "collector-final.log",
            own_group=False,
        )


def cleanup_namespace(k, namespace, owner, evidence):
    """Delete only a namespace carrying this run's ownership marker."""
    try:
        observed = run(
            [*k, "get", "namespace", namespace, "--ignore-not-found", "-o", "json"],
            timeout=15,
            check=False,
        )
        (evidence / "namespace-before-cleanup.json").write_text(
            observed.stdout + observed.stderr
        )
        if observed.returncode:
            raise RuntimeError("could not verify collector namespace ownership")
        if not observed.stdout.strip():
            (evidence / "collector-cleanup.log").write_text(
                "Collector namespace is absent.\n"
            )
            return None
        metadata = json.loads(observed.stdout)["metadata"]
        if metadata.get("labels", {}).get("openshell.ai/trace-test-run") != owner:
            raise RuntimeError("collector namespace ownership does not match this run")
        cleanup = run(
            [
                *k,
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=60s",
            ],
            timeout=90,
            check=False,
        )
        (evidence / "collector-cleanup.log").write_text(cleanup.stdout + cleanup.stderr)
        if cleanup.returncode:
            raise RuntimeError("collector namespace deletion failed")
    except (
        OSError,
        ValueError,
        KeyError,
        subprocess.TimeoutExpired,
        RuntimeError,
    ) as error:
        (evidence / "collector-cleanup-error.log").write_text(str(error) + "\n")
        return f"collector cleanup failed for {namespace}: {error}"
    return None


def execute():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    cli = str(
        Path(os.getenv("OPENSHELL_BIN", ROOT / "target/debug/openshell")).resolve()
    )
    if not Path(cli).is_file():
        raise RuntimeError("build openshell-cli first or set OPENSHELL_BIN")
    if args.check:
        check_receipt(
            Path(os.environ["OPENSHELL_E2E_TRACING_EVIDENCE"]),
            os.environ["OPENSHELL_E2E_TRACING_NAMESPACE"],
            os.environ["OPENSHELL_E2E_TRACING_GATEWAY"],
            cli,
        )
        return
    if os.getenv("OPENSHELL_E2E_KUBE_DB_SCENARIOS", "0") != "0":
        raise RuntimeError("the tracing probe uses one isolated gateway install")
    owner = uuid.uuid4().hex
    suffix = owner[:12]
    namespace = "openshell-tracing-" + suffix
    gateway_name = "tracing-" + suffix
    evidence = ROOT / "results/kubernetes-tracing" / suffix
    evidence.mkdir(parents=True)
    k = kubectl(namespace)  # Validate context before any cluster mutation.
    manifest = json.dumps(collector_manifest(namespace), indent=2)
    (evidence / "collector.json").write_text(manifest + "\n")
    (evidence / "inputs.json").write_text(
        json.dumps(
            {
                "cli_path": cli,
                "cli_sha256": hashlib.sha256(Path(cli).read_bytes()).hexdigest(),
                "source_head": run(
                    ["git", "-C", str(ROOT), "rev-parse", "HEAD"]
                ).stdout.strip(),
                "source_status": run(
                    ["git", "-C", str(ROOT), "status", "--short"]
                ).stdout,
                "images": {
                    key: os.environ.get(key)
                    for key in (
                        "IMAGE_TAG",
                        "GATEWAY_IMAGE",
                        "SUPERVISOR_IMAGE",
                        "SANDBOX_IMAGE",
                    )
                },
                "collector_image": COLLECTOR_IMAGE,
                "context": os.environ["OPENSHELL_E2E_KUBE_CONTEXT"],
            },
            indent=2,
        )
        + "\n"
    )
    creation_started = False
    try:
        creation_started = True
        namespace_manifest = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {"openshell.ai/trace-test-run": owner},
            },
        }
        run([*k, "create", "-f", "-"], input=json.dumps(namespace_manifest))
        run([*k, "apply", "-f", "-"], input=manifest)
        run(
            [*k, "rollout", "status", "deployment/collector", "--timeout=120s"],
            timeout=150,
        )
        with tempfile.TemporaryDirectory(prefix="openshell-tracing-") as work:
            values = Path(work) / "tracing.json"
            values.write_text(json.dumps(gateway_values(namespace, gateway_name)))
            (evidence / "values.json").write_text(values.read_text())
            env = os.environ.copy()
            existing = env.get("OPENSHELL_E2E_KUBE_EXTRA_VALUES", "")
            env.update(
                OPENSHELL_BIN=cli,
                OPENSHELL_E2E_KUBE_EXTRA_VALUES=":".join(
                    filter(None, [existing, str(values)])
                ),
                OPENSHELL_E2E_TRACING_EVIDENCE=str(evidence),
                OPENSHELL_E2E_TRACING_NAMESPACE=namespace,
                OPENSHELL_E2E_TRACING_GATEWAY=gateway_name,
            )
            result = run(
                [
                    "bash",
                    str(ROOT / "e2e/with-kube-gateway.sh"),
                    sys.executable,
                    str(HERE / "run.py"),
                    "--check",
                ],
                timeout=1200,
                check=False,
                log_path=evidence / "gateway-harness.log",
                termination_grace=180,
                env=env,
            )
            if result.returncode:
                raise RuntimeError(
                    f"Kubernetes trace validation failed; evidence: {evidence}"
                )
            confirm_receipt(evidence, gateway_name)
    finally:
        failed = sys.exc_info()[0] is not None
        if creation_started:
            for filename, command in [
                (
                    "collector-final.log",
                    ["logs", "deployment/collector", "-c", "collector"],
                ),
                ("collector-pods.json", ["get", "pods", "-o", "json"]),
            ]:
                capture([*k, *command], evidence / filename)
            error = cleanup_namespace(k, namespace, owner, evidence)
            if error and failed:
                print(error, file=sys.stderr)
            elif error:
                raise RuntimeError(error)
    print(f"Trace receipt evidence: {evidence}")


def main():
    with termination_signals():
        execute()


if __name__ == "__main__":
    main()
