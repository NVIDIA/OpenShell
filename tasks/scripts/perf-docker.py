#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Paired Docker versus OpenShell driver benchmark; see benchmarks/docker/README.md."""

import argparse
import datetime
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COUNTS = {
    "cpu": 100_000_000,
    "getpid": 1_000_000,
    "file": 50_000,
    "spawn": 200,
    "tcp-connect": 1_000,
    "tcp-stream": 20_000,
}
# File-open attribution controls. They run after the cases above, so adding
# them changes neither the order nor the definition of the original six.
ATTRIBUTION_COUNTS = {
    # Open and close only, no read.
    "file-open": 50_000,
    # Reads on one descriptor opened before the timer: no open is measured.
    "file-read": 500_000,
    # The `file` operation split across 4 and 16 threads.
    "file-t4": 50_000,
    "file-t16": 50_000,
    # The `file` operation with per-iteration latency percentiles.
    "file-latency": 50_000,
}
LATENCY_FIELDS = ("p50_ns", "p99_ns", "max_ns")


def case_order(trial, attribution):
    """Return the measured cases for a trial.

    The original cases keep the shuffle they have always had for a trial.
    Attribution cases are shuffled separately and appended.
    """
    cases = list(COUNTS)
    random.Random(trial).shuffle(cases)
    if attribution:
        extra = list(ATTRIBUTION_COUNTS)
        random.Random(f"attribution-{trial}").shuffle(extra)
        cases += extra
    return cases


def validate_result(result, case, count):
    """Reject workload output that does not describe the requested case."""
    if (
        result.get("case") != case
        or result.get("iterations") != count
        or not result.get("elapsed_ns", 0) > 0
        or result.get("uid") != 1000
        or result.get("gid") != 1000
        or result.get("cwd") != "/sandbox"
    ):
        return False
    if case == "file-latency":
        return all(result.get(field, 0) > 0 for field in LATENCY_FIELDS) and (
            result["p50_ns"] <= result["p99_ns"] <= result["max_ns"]
        )
    return True


def run(command, timeout=300):
    start = time.perf_counter_ns()
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    elapsed = time.perf_counter_ns() - start
    if result.returncode:
        raise RuntimeError(
            f"{command!r} exited {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout, elapsed


def summary(samples):
    return {
        "median_ns": statistics.median(samples),
        "min_ns": min(samples),
        "max_ns": max(samples),
        "samples": len(samples),
    }


def report(data):
    rows = [
        "# Docker versus OpenShell Docker driver",
        "",
        f"Run: {data['started_utc']}; commit: `{data['commit']}`.",
        f"Complete: {data.get('complete', False)}.",
        "",
        "Times are medians across paired trials. Range is min-max; overhead is the median",
        "of each trial's OpenShell/Docker ratio minus one. Workload timers exclude exec transport.",
        "Provisioning and exec include the client and control plane. Lower times are better.",
        "",
        "| Case | Docker ms (range) | OpenShell ms (range) | Paired overhead |",
        "|---|---:|---:|---:|",
    ]
    for case in ["provision", "exec", *COUNTS, *ATTRIBUTION_COUNTS]:
        samples = {
            mode: {
                r["trial"]: r["elapsed_ns"]
                for r in data["samples"]
                if r["mode"] == mode and r["case"] == case
            }
            for mode in ("docker", "openshell")
        }
        if (
            not samples["docker"]
            or samples["docker"].keys() != samples["openshell"].keys()
        ):
            continue
        stats = [summary(list(samples[mode].values())) for mode in samples]
        ratios = [
            samples["openshell"][i] / samples["docker"][i] - 1
            for i in samples["docker"]
        ]
        cells = [
            f"{s['median_ns'] / 1e6:.3f} ({s['min_ns'] / 1e6:.3f}-{s['max_ns'] / 1e6:.3f})"
            for s in stats
        ]
        rows.append(
            f"| {case} | {cells[0]} | {cells[1]} | {statistics.median(ratios):+.1%} |"
        )
    latency = {
        mode: [
            r
            for r in data["samples"]
            if r["mode"] == mode and r["case"] == "file-latency"
        ]
        for mode in ("docker", "openshell")
    }
    if latency["docker"] and latency["openshell"]:
        rows += [
            "",
            "Per-operation latency of the `file` operation (`file-latency`), median across",
            "trials. Each timed interval includes two clock reads.",
            "",
            "| Mode | p50 ns | p99 ns | max ns |",
            "|---|---:|---:|---:|",
        ]
        for mode, samples in latency.items():
            cells = [
                f"{statistics.median(r[field] for r in samples):.0f}"
                for field in LATENCY_FIELDS
            ]
            rows.append(f"| {mode} | {' | '.join(cells)} |")
    rows += [
        "",
        "`file-open` omits the read, `file-read` omits the open, and `file-t4`/`file-t16`",
        "split the `file` operation across threads. Compare each with `file`.",
        "",
        "See results.json for raw samples, image identities, container settings, and host metadata.",
        "",
    ]
    return "\n".join(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="openshell-perf-workload:local")
    parser.add_argument("--openshell", default="openshell")
    parser.add_argument("--gateway", default="docker-dev")
    parser.add_argument("--trials", type=int, default=9)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument("--output", type=Path, default=ROOT / ".cache/perf-docker")
    parser.add_argument(
        "--attribution",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="also run the file-open attribution cases after the original six",
    )
    args = parser.parse_args()
    if args.trials < 1 or args.warmups < 0 or not 0 < args.scale <= 100:
        parser.error("trials must be positive, warmups nonnegative, scale in (0, 100]")
    for binary in ("docker", args.openshell):
        if not shutil.which(binary):
            parser.error(f"missing executable: {binary}")
    cli = [args.openshell, "--gateway", args.gateway]
    docker_info = json.loads(run(["docker", "info", "--format", "{{json .}}"])[0])
    # A host-local daemon is required: timing remote exec would add asymmetric transport.
    endpoint = (
        os.environ.get("DOCKER_HOST")
        or run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"]
        )[0].strip()
    )
    if not endpoint.startswith("unix://"):
        parser.error("benchmark requires a local Unix-socket Docker daemon")
    image = json.loads(run(["docker", "image", "inspect", args.image])[0])[0]
    image_id = image["Id"]
    selected = dict(COUNTS, **(ATTRIBUTION_COUNTS if args.attribution else {}))
    counts = {case: max(1, int(n * args.scale)) for case, n in selected.items()}
    args.output.mkdir(parents=True, exist_ok=True)
    policy = ROOT / "benchmarks/docker/policy.yaml"
    data = {
        "started_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "commit": run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])[0].strip(),
        "dirty_tree": run(["git", "-C", str(ROOT), "status", "--short"])[0],
        "host": platform.uname()._asdict(),
        "cpu": Path("/proc/cpuinfo").read_text(),
        "docker_server": {
            k: docker_info.get(k)
            for k in (
                "ServerVersion",
                "KernelVersion",
                "OperatingSystem",
                "Architecture",
                "NCPU",
                "MemTotal",
                "Driver",
                "SecurityOptions",
            )
        },
        "openshell_version": run([args.openshell, "--version"])[0].strip(),
        "image": image,
        "counts": counts,
        "warmups": args.warmups,
        "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                Path(__file__).resolve(),
                ROOT / "benchmarks/docker/workload.c",
                ROOT / "benchmarks/docker/Dockerfile",
            ]
        },
        "containers": [],
        "samples": [],
        "complete": False,
    }

    def save():
        (args.output / "results.json").write_text(json.dumps(data, indent=2) + "\n")
        (args.output / "report.md").write_text(report(data))

    save()
    try:
        for trial in range(args.trials):
            modes = (
                ["docker", "openshell"] if trial % 2 == 0 else ["openshell", "docker"]
            )
            cases = case_order(trial, args.attribution)
            for mode in modes:
                name = f"perf-{uuid.uuid4().hex[:12]}"
                cleanup = (
                    ["docker", "rm", "-f", name]
                    if mode == "docker"
                    else [*cli, "sandbox", "delete", name]
                )
                created = set()
                try:
                    before = set(run(["docker", "ps", "-aq"])[0].split())
                    if mode == "docker":
                        create = [
                            "docker",
                            "run",
                            "-d",
                            "--name",
                            name,
                            "--network",
                            "none",
                            "--cap-drop",
                            "ALL",
                            "--security-opt",
                            "no-new-privileges",
                            image_id,
                        ]
                    else:
                        create = [
                            *cli,
                            "sandbox",
                            "create",
                            "--name",
                            name,
                            "--from",
                            image_id,
                            "--policy",
                            str(policy),
                            "--no-auto-providers",
                            "--no-tty",
                            "--detach",
                            "--",
                            "/bin/sleep",
                            "infinity",
                        ]
                    _, provision_ns = run(create)
                    prefix = (
                        ["docker", "exec", name]
                        if mode == "docker"
                        else [
                            *cli,
                            "sandbox",
                            "exec",
                            "--name",
                            name,
                            "--no-tty",
                            "--no-login-shell",
                            "--",
                        ]
                    )
                    # Readiness is included in provisioning for both modes.
                    _, ready_ns = run([*prefix, "/bin/true"])
                    data["samples"].append(
                        {
                            "trial": trial,
                            "mode": mode,
                            "case": "provision",
                            "elapsed_ns": provision_ns + ready_ns,
                        }
                    )
                    after = set(run(["docker", "ps", "-aq"])[0].split())
                    created = after - before
                    configs = (
                        json.loads(run(["docker", "inspect", *sorted(created)])[0])
                        if created
                        else []
                    )
                    workloads = [
                        c
                        for c in configs
                        if c["Image"] == image_id and c["State"]["Running"]
                    ]
                    if len(workloads) != 1:
                        raise RuntimeError(
                            "expected exactly one running workload with the pinned image on the local Docker daemon"
                        )
                    workload = workloads[0]
                    if mode == "openshell" and "openshell-sandbox" not in json.dumps(
                        workload["Config"].get("Entrypoint")
                    ):
                        raise RuntimeError(
                            "OpenShell did not launch the sandbox runtime through the Docker driver"
                        )
                    # Store only execution settings, never environment/credential values.
                    data["containers"].append(
                        {
                            "trial": trial,
                            "mode": mode,
                            "settings": [
                                {
                                    "image": c["Image"],
                                    "path": c["Path"],
                                    "user": c["Config"]["User"],
                                    "working_dir": c["Config"]["WorkingDir"],
                                    "apparmor_profile": c["AppArmorProfile"],
                                    "host_config": c["HostConfig"],
                                }
                                for c in configs
                            ],
                        }
                    )
                    for _ in range(args.warmups):
                        run([*prefix, "/bin/true"])
                    _, exec_ns = run([*prefix, "/bin/true"])
                    data["samples"].append(
                        {
                            "trial": trial,
                            "mode": mode,
                            "case": "exec",
                            "elapsed_ns": exec_ns,
                        }
                    )
                    for case in cases:
                        command = [
                            *prefix,
                            "/usr/local/bin/workload",
                            case,
                            str(counts[case]),
                        ]
                        for _ in range(args.warmups):
                            run(command)
                        output, transport_ns = run(command)
                        result = json.loads(output)
                        if not validate_result(result, case, counts[case]):
                            raise RuntimeError(f"invalid workload output: {output}")
                        data["samples"].append(
                            dict(
                                result,
                                trial=trial,
                                mode=mode,
                                transport_ns=transport_ns,
                            )
                        )
                        save()
                        print(
                            f"trial {trial + 1}/{args.trials} {mode} {case}: {result['elapsed_ns'] / 1e6:.3f} ms",
                            flush=True,
                        )
                finally:
                    run(cleanup)
                    # OpenShell deletion is asynchronous. Wait until its containers
                    # are gone before starting the next measured mode.
                    deadline = time.monotonic() + 30
                    while created & set(run(["docker", "ps", "-aq"])[0].split()):
                        if time.monotonic() >= deadline:
                            raise RuntimeError(
                                "timed out waiting for benchmark container cleanup"
                            )
                        time.sleep(0.1)
        data["complete"] = True
    except BaseException as error:
        data["error"] = str(error)
        raise
    finally:
        save()
    print(report(data))


if __name__ == "__main__":
    main()
