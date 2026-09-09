# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run response tests through a PR-built gateway and Docker sandbox."""

import base64
import itertools
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

SUITE = Path(__file__).parent.resolve()
ROOT = SUITE.parents[1]
OUT = Path(os.environ.get("MIDDLEWARE_LIVE_OUTPUT", SUITE / "output")).resolve()
OUT.mkdir(parents=True, exist_ok=True)
CLI = [
    str(ROOT / "target/debug/openshell"),
    "--gateway-endpoint",
    "http://127.0.0.1:18201",
]
NAME = "pr3074-live"
ORIGINAL = "alpha secret omega\n"


def command(args, **kwargs):
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, **kwargs)
    if r.returncode:
        raise RuntimeError(f"Command failed: {args[:6]}\n{r.stdout}\n{r.stderr}")
    return r.stdout


def policy(stages):
    p = {
        "version": 1,
        "network_policies": {
            "upstream": {
                "name": "Live fixture",
                "endpoints": [
                    {
                        "host": "host.openshell.internal",
                        "port": 18081,
                        "protocol": "rest",
                        "rules": [{"allow": {"method": "*", "path": "/**"}}],
                    }
                ],
                "binaries": [{"path": "/usr/bin/curl"}],
            }
        },
    }
    if stages:
        p["network_middlewares"] = {}
        for i, stage in enumerate(stages):
            config = dict(stage)
            service = config.pop("service", i + 1)
            on_error = config.pop("on_error", "fail_closed")
            p["network_middlewares"][f"stage-{i + 1}"] = {
                "name": f"Stage {i + 1}",
                "middleware": f"fixture-{service}",
                "order": (i + 1) * 10,
                "config": config,
                "on_error": on_error,
                "endpoints": {"include": ["host.openshell.internal"]},
            }
    return p


def set_policy(stages, label):
    path = OUT / "policies" / f"{label}.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(yaml.safe_dump(policy(stages)))
    output = command([*CLI, "policy", "set", NAME, "--policy", str(path), "--wait"])
    with (OUT / "policy-updates.log").open("a") as f:
        f.write(label + "\n" + output)


CLIENT = """import subprocess,json,base64
for path in ["/tmp/pr3074-head","/tmp/pr3074-body"]: open(path,"wb").close()
r=subprocess.run(["curl","-sS","--max-time","5","-D","/tmp/pr3074-head","-o","/tmp/pr3074-body","-w","%{json}",*ARGS],capture_output=True)
print(json.dumps({"curl_code":r.returncode,"stderr":r.stderr.decode(),"metrics":json.loads(r.stdout),"headers":open("/tmp/pr3074-head").read(),"body_b64":base64.b64encode(open("/tmp/pr3074-body","rb").read()).decode()}))
"""


def request(path="/fixed", method="GET"):
    args = (["--head"] if method == "HEAD" else []) + [
        "http://host.openshell.internal:18081" + path
    ]
    result = command(
        [
            *CLI,
            "sandbox",
            "exec",
            "--name",
            NAME,
            "--no-tty",
            "--",
            "python3",
            "-c",
            "ARGS=" + repr(args) + "\n" + CLIENT,
        ]
    )
    return json.loads(result.strip())


def cases():
    c = []

    def add(name, stages, body=ORIGINAL, status=200, path="/fixed", code=0, **extra):
        c.append(
            dict(
                name=name,
                stages=stages,
                expected_body=body,
                status=status,
                path=path,
                code=code,
                **extra,
            )
        )

    add("baseline", [])
    for mode in [1, 2, 3]:
        add(f"single-{mode}-pass", [{"mode": mode}])
        add(f"single-{mode}-skip", [{"mode": mode, "preflight": "skip"}])
        add(
            f"single-{mode}-header",
            [{"mode": mode, "header": "added"}],
            header="x-live-test: added",
        )
        add(
            f"single-{mode}-preflight-block",
            [{"mode": mode, "preflight": "block_delivery"}],
            body=None,
            status=403,
        )
    for mode in [2, 3]:
        add(
            f"single-{mode}-transform",
            [{"mode": mode, "body": "transform"}],
            body=ORIGINAL.replace("secret", "[REDACTED]"),
            absent_header="etag:",
        )
        add(
            f"single-{mode}-delete",
            [{"mode": mode, "body": "transform", "delete": True}],
            body="",
        )
        add(
            f"single-{mode}-body-block",
            [{"mode": mode, "body": "block_delivery"}],
            body=None if mode == 2 else "",
            status=403 if mode == 2 else 200,
            code=0 if mode == 2 else 18,
        )
        add(f"single-{mode}-skip-remaining", [{"mode": mode, "body": "skip_remaining"}])
        for error in ["invalid_sequence", "timeout", "abort"]:
            for failure in ["fail_open", "fail_closed"]:
                closed = failure == "fail_closed"
                add(
                    f"single-{mode}-{error}-{failure}",
                    [{"mode": mode, "body": error, "on_error": failure}],
                    body=None if closed and mode == 2 else "" if closed else ORIGINAL,
                    status=502 if closed and mode == 2 else 200,
                    code=18 if closed and mode == 3 else 0,
                )
    for failure in ["fail_open", "fail_closed"]:
        for action in ["timeout", "abort"]:
            add(
                f"preflight-{action}-{failure}",
                [{"preflight": action, "on_error": failure}],
                body=ORIGINAL if failure == "fail_open" else None,
                status=200 if failure == "fail_open" else 502,
            )
        add(
            f"preflight-invalid-mode-{failure}",
            [{"mode": 99, "on_error": failure}],
            body=ORIGINAL if failure == "fail_open" else None,
            status=200 if failure == "fail_open" else 502,
        )
        add(
            f"protected-header-{failure}",
            [
                {
                    "mode": 1,
                    "header": "123",
                    "header_name": "content-length",
                    "on_error": failure,
                }
            ],
            body=ORIGINAL if failure == "fail_open" else None,
            status=200 if failure == "fail_open" else 502,
        )
    for modes in itertools.product([1, 2, 3], repeat=2):
        stages = [
            {
                "mode": mode,
                "body": "transform",
                "find": "secret" if i == 0 else "TOKEN",
                "replace": "TOKEN" if i == 0 else "FINAL",
                "header": str(i),
            }
            for i, mode in enumerate(modes)
        ]
        body = ORIGINAL.replace("secret", "TOKEN") if modes[0] != 1 else ORIGINAL
        if modes[1] != 1:
            body = body.replace("TOKEN", "FINAL")
        add(
            "pair-" + "-".join(map(str, modes)),
            stages,
            body=body,
            header="x-live-test: 1",
        )
    for modes in [[2, 2, 2], [3, 3, 3], [1, 2, 3], [3, 2, 3], [2, 3, 2]]:
        add(
            "triple-" + "-".join(map(str, modes)),
            [
                {"mode": m, "body": "transform", "find": a, "replace": b}
                for m, a, b in zip(
                    modes, ["secret", "A", "B"], ["A", "B", "C"], strict=False
                )
            ],
            body=ORIGINAL.replace("secret", "C") if modes[0] != 1 else ORIGINAL,
        )
    add(
        "skip-stage-continues-chain",
        [{"mode": 3, "body": "skip_remaining"}, {"mode": 3, "body": "transform"}],
        path="/slow",
        body=ORIGINAL.replace("secret", "[REDACTED]"),
    )
    add(
        "skip-transform-continues-chain",
        [
            {
                "mode": 3,
                "body": "skip_remaining",
                "skip_transform": True,
                "find": "alpha",
                "replace": "FIRST",
            },
            {"mode": 2, "body": "transform"},
        ],
        path="/slow",
        body="FIRST [REDACTED] omega\n",
    )
    add(
        "fail-open-continues-chain",
        [
            {"mode": 3, "body": "invalid_sequence", "on_error": "fail_open"},
            {"mode": 2, "body": "transform"},
        ],
        path="/slow",
        body=ORIGINAL.replace("secret", "[REDACTED]"),
    )
    add(
        "block-overrides-fail-open",
        [{"mode": 2, "body": "block_delivery", "on_error": "fail_open"}, {"mode": 2}],
        body=None,
        status=403,
    )
    add(
        "stream-then-whole-block",
        [{"mode": 3}, {"mode": 2, "body": "block_delivery"}],
        body=None,
        status=403,
        path="/slow",
    )
    add(
        "whole-then-stream-block",
        [{"mode": 2}, {"mode": 3, "body": "block_delivery"}],
        body=None,
        status=403,
        path="/slow",
    )
    add(
        "late-stream-block",
        [{"mode": 3, "body": "block_delivery", "block_seq": 2}],
        body="alpha ",
        path="/slow",
        code=18,
    )
    add(
        "stream-split-token",
        [{"mode": 3, "body": "transform"}],
        body="secret",
        path="/split",
    )
    add(
        "whole-split-token",
        [{"mode": 2, "body": "transform"}],
        body="[REDACTED]",
        path="/split",
    )
    for mode in [2, 3]:
        add(f"empty-{mode}", [{"mode": mode}], body="", path="/empty")
        add(
            f"trailers-{mode}",
            [{"mode": mode, "trailer": True}],
            path="/trailers",
            header="x-check: changed",
        )
    for path in ["/bodyless", "/range", "/encoded", "/no-transform"]:
        add(
            "headers-only" + path.replace("/", "-"),
            [{"mode": 1}],
            body="" if path == "/bodyless" else None,
            status=204 if path == "/bodyless" else 206 if path == "/range" else 200,
            path=path,
            modes=[1],
        )
        add(
            "illegal-whole" + path.replace("/", "-"),
            [{"mode": 2}],
            body=None,
            status=502,
            path=path,
        )
    add("head", [{"mode": 1}], body=None, method="HEAD", modes=[1])
    add(
        "small-limit-stream",
        [{"service": 4, "mode": 3}],
        body="x" * 100,
        path="/fixed?size=100",
    )
    add(
        "small-limit-whole-known-closed",
        [{"service": 4, "mode": 2}],
        body=None,
        status=502,
        path="/fixed?size=100",
    )
    add(
        "small-limit-whole-unknown-closed",
        [{"service": 4, "mode": 2}],
        body=None,
        status=502,
        path="/chunked?size=100",
    )
    add(
        "small-limit-whole-unknown-open",
        [{"service": 4, "mode": 2, "on_error": "fail_open"}, {"mode": 3}],
        body="x" * 100,
        path="/chunked?size=100",
    )
    add(
        "different-limits-and-modes",
        [{"service": 4, "mode": 3}, {"mode": 2}],
        body="x" * 100,
        path="/fixed?size=100",
    )
    add(
        "growth-over-next-stage-limit",
        [
            {"mode": 2, "body": "transform", "append": "x" * 40},
            {"service": 4, "mode": 2},
        ],
        body=None,
        status=502,
    )
    add(
        "preflight-content-length-contract",
        [{"mode": 1}],
        preflight_header={"name": "content-length", "value": "19"},
    )
    add(
        "stream-over-total-limit",
        [{"mode": 3}],
        body="x" * 1048576,
        path="/fixed?size=1048576",
    )
    add(
        "stream-pair-over-total-limit",
        [{"mode": 3}, {"mode": 3}],
        body="x" * 1048576,
        path="/fixed?size=1048576",
    )
    return c


def matrix():
    results = []
    for case in cases():
        if len(sys.argv) > 2 and sys.argv[2] not in case["name"]:
            continue
        name = case["name"]
        set_policy(case["stages"], name)
        start = (OUT / "events.jsonl").stat().st_size
        result = request(case["path"], case.get("method", "GET"))
        time.sleep(0.025)
        with (OUT / "events.jsonl").open() as f:
            f.seek(start)
            events = [json.loads(line) for line in f if line.strip()]
        body = base64.b64decode(result["body_b64"])
        checks = {
            "status": result["metrics"]["http_code"] == case["status"],
            "curl_code": result["curl_code"] == case["code"],
        }
        if case["expected_body"] is not None:
            checks["body"] = body == case["expected_body"].encode()
        if "header" in case:
            checks["header"] = case["header"] in result["headers"].lower()
        if "absent_header" in case:
            checks["absent_header"] = (
                case["absent_header"] not in result["headers"].lower()
            )
        if "modes" in case:
            checks["modes"] = all(
                e["modes"] == case["modes"] for e in events if e["kind"] == "preflight"
            ) and bool(events)
        if "preflight_header" in case:
            checks["preflight_header"] = any(
                case["preflight_header"] in e.get("headers", [])
                for e in events
                if e["kind"] == "preflight"
            )
        if case["status"] in [403, 502]:
            checks["canonical_error"] = json.loads(body)["error"] == (
                "middleware_denied"
                if case["status"] == 403
                else "response_delivery_failed"
            )
        record = {
            "case": case,
            "result": result,
            "events": events,
            "checks": checks,
            "passed": all(checks.values()),
        }
        (OUT / "responses").mkdir(exist_ok=True)
        (OUT / "responses" / (name + ".json")).write_text(json.dumps(record, indent=2))
        results.append(record)
        print(
            ("PASS" if record["passed"] else "FAIL")
            + " "
            + name
            + " "
            + json.dumps(checks),
            flush=True,
        )
        (OUT / "matrix-results.json").write_text(json.dumps(results, indent=2))
    return 1 if not results or any(not result["passed"] for result in results) else 0


if __name__ == "__main__":
    if sys.argv[1] == "create":
        path = OUT / "initial-policy.yaml"
        path.write_text(yaml.safe_dump(policy([])))
        print(
            command(
                [
                    *CLI,
                    "sandbox",
                    "create",
                    "--name",
                    NAME,
                    "--policy",
                    str(path),
                    "--from",
                    str(SUITE / "Dockerfile"),
                    "--no-tty",
                    "--detach",
                    "--",
                    "sleep",
                    "infinity",
                ]
            )
        )
    elif sys.argv[1] == "matrix":
        sys.exit(matrix())
    elif sys.argv[1] == "probe":
        print(json.dumps(request(), indent=2))
