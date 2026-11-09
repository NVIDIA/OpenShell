# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real process controls for timeout, cancellation, teardown and partial logs."""

import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path
from unittest import mock

import run


def wait_for(path):
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"process did not become ready: {path}")
        time.sleep(0.01)


def harness(root, *, ignore_term=False):
    child = root / "child.py"
    ready = root / "ready"
    heartbeat = root / "heartbeat"
    pid = root / "child-pid"
    cleanup = root / "cleanup"
    child.write_text(
        "import os,signal,time\nfrom pathlib import Path\n"
        + ("signal.signal(signal.SIGTERM,signal.SIG_IGN)\n" if ignore_term else "")
        + f"Path({str(pid)!r}).write_text(str(os.getpid()))\n"
        + f"Path({str(heartbeat)!r}).write_text('starting')\n"
        + f"Path({str(ready)!r}).write_text('ready')\n"
        + f"while True:\n Path({str(heartbeat)!r}).write_text(str(time.monotonic_ns()))\n time.sleep(0.02)\n"
    )
    # Exercise the signal/EXIT contract installed in the actual gateway harness.
    traps = "\n".join(
        line
        for line in (run.ROOT / "e2e/with-kube-gateway.sh").read_text().splitlines()
        if line.startswith("trap ")
    )
    script = root / "harness.sh"
    script.write_text(
        f"cleanup() {{ printf cleaned > {shlex.quote(str(cleanup))}; }}\n"
        + traps
        + "\n"
        + f"{shlex.quote(sys.executable)} {shlex.quote(str(child))} &\n"
        + f"while [ ! -f {shlex.quote(str(ready))} ]; do sleep 0.01; done\n"
        + "echo 'harness started'\nwait\n"
    )
    return script, ready, heartbeat, pid, cleanup


def stop_test_child(pid_path):
    if pid_path.exists():
        with suppress(ProcessLookupError):
            os.kill(int(pid_path.read_text()), signal.SIGKILL)


class LifecycleTest(unittest.TestCase):
    def assert_child_stopped(self, heartbeat):
        before = heartbeat.read_text()
        time.sleep(0.15)
        self.assertEqual(
            before, heartbeat.read_text(), "owned child is still doing work"
        )

    def test_timeout_runs_harness_cleanup_and_retains_partial_log(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            script, _, heartbeat, pid, cleanup = harness(root)
            output = root / "harness.log"
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run.run(
                        ["bash", str(script)],
                        timeout=0.3,
                        termination_grace=0.3,
                        log_path=output,
                    )
                self.assertTrue(
                    cleanup.exists(), "the harness EXIT cleanup did not run"
                )
                self.assertIn("harness started", output.read_text())
                self.assert_child_stopped(heartbeat)
            finally:
                stop_test_child(pid)

    def test_completed_harness_reclaims_background_children_and_preserves_status(self):
        for code in [0, 7]:
            with self.subTest(exit_code=code), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                script, _, heartbeat, pid, cleanup = harness(root, ignore_term=True)
                script.write_text(
                    script.read_text().replace(
                        "echo 'harness started'\nwait\n",
                        f"echo 'harness started'\nexit {code}\n",
                    )
                )
                try:
                    result = run.run(
                        ["bash", str(script)],
                        check=False,
                        termination_grace=0.3,
                        log_path=root / "harness.log",
                    )
                    self.assertEqual(result.returncode, code)
                    self.assertTrue(cleanup.exists())
                    self.assert_child_stopped(heartbeat)
                finally:
                    stop_test_child(pid)

    def test_timeout_escalates_for_a_child_ignoring_termination(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            script, _, heartbeat, pid, cleanup = harness(root, ignore_term=True)
            started = time.monotonic()
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    run.run(
                        ["bash", str(script)],
                        timeout=0.3,
                        termination_grace=0.3,
                        log_path=root / "harness.log",
                    )
                self.assertLess(time.monotonic() - started, 3)
                self.assertTrue(cleanup.exists())
                self.assert_child_stopped(heartbeat)
            finally:
                stop_test_child(pid)

    def test_handled_signals_stop_descendants_and_run_exit_cleanup(self):
        for number in [signal.SIGINT, signal.SIGTERM]:
            with self.subTest(signal=number), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                script, ready, heartbeat, pid, cleanup = harness(root, ignore_term=True)
                probe = root / "probe.py"
                probe.write_text(
                    f"import sys\nsys.path.insert(0,{str(Path(run.__file__).parent)!r})\nimport run\n"
                    + "with run.termination_signals():\n"
                    + f" run.run(['bash',{str(script)!r}],timeout=30,termination_grace=0.3,log_path=__import__('pathlib').Path({str(root / 'harness.log')!r}))\n"
                )
                process = subprocess.Popen(
                    [sys.executable, str(probe)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    wait_for(ready)
                    os.kill(process.pid, number)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 128 + number, stdout + stderr)
                    self.assertTrue(cleanup.exists())
                    self.assert_child_stopped(heartbeat)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    stop_test_child(pid)

    def test_cancellation_cleans_created_namespace_and_preserves_failure(self):
        for phase in ["create", "apply"]:
            for cleanup_fails in [False, True]:
                with (
                    self.subTest(phase=phase, cleanup_fails=cleanup_fails),
                    tempfile.TemporaryDirectory() as work,
                ):
                    root = Path(work)
                    cli = root / "cli"
                    cli.write_text("unused test CLI")
                    probe = root / "cancel.py"
                    probe.write_text(
                        "import json,os,signal,subprocess,sys\nfrom pathlib import Path\nfrom unittest import mock\n"
                        + f"sys.path.insert(0,{str(Path(run.__file__).parent)!r})\nimport run\n"
                        + f"root=Path({str(root)!r}); owner={{}}\n"
                        + "def fake(command,**kwargs):\n"
                        + " with (root/'calls.jsonl').open('a') as out: out.write(json.dumps(command)+'\\n')\n"
                        + " if 'create' in command: owner.update(json.loads(kwargs['input']))\n"
                        + f" if {phase!r} in command: os.kill(os.getpid(),signal.SIGTERM)\n"
                        + " text=json.dumps(owner) if 'get' in command and 'namespace' in command else ''\n"
                        + f" return subprocess.CompletedProcess(command,1 if {cleanup_fails!r} and 'delete' in command else 0,text,'')\n"
                        + "with mock.patch.object(run,'ROOT',root),mock.patch.object(run,'run',fake),"
                        + f"mock.patch.dict(os.environ,{{'OPENSHELL_BIN':{str(cli)!r},'OPENSHELL_E2E_KUBE_CONTEXT':'fake-disposable'}},clear=True),"
                        + "mock.patch.object(sys,'argv',['run.py']): run.main()\n"
                    )
                    process = subprocess.run(
                        [sys.executable, str(probe)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    self.assertEqual(process.returncode, 143, process.stderr)
                    calls = [
                        json.loads(line)
                        for line in (root / "calls.jsonl").read_text().splitlines()
                    ]
                    self.assertTrue(
                        any(
                            "delete" in command and "namespace" in command
                            for command in calls
                        )
                    )
                    if cleanup_fails:
                        self.assertIn("collector cleanup failed", process.stderr)

    def test_cleanup_does_not_delete_a_namespace_owned_by_another_run(self):
        with tempfile.TemporaryDirectory() as work:
            result = subprocess.CompletedProcess(
                [],
                0,
                json.dumps(
                    {"metadata": {"labels": {"openshell.ai/trace-test-run": "other"}}}
                ),
                "",
            )
            with mock.patch.object(run, "run", return_value=result) as invoked:
                error = run.cleanup_namespace(
                    ["kubectl"], "test-namespace", "this-run", Path(work)
                )
            self.assertIn("ownership", error)
            self.assertFalse(
                any("delete" in call.args[0] for call in invoked.call_args_list)
            )

    def test_forced_shutdown_reaches_nested_probe_cleanup(self):
        for number in [None, signal.SIGINT, signal.SIGTERM]:
            with self.subTest(signal=number), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                cli = root / "cli"
                ready = root / "create-ready"
                heartbeat = root / "cleanup-heartbeat"
                cli.write_text(
                    f"#!{sys.executable}\n"
                    "import os,signal,sys,time\nfrom pathlib import Path\n"
                    + f"root=Path({str(root)!r})\n"
                    + "operation=sys.argv[2]\n"
                    + "(root/(operation+'-pid')).write_text(str(os.getpid()))\n"
                    + "if operation=='create': (root/'create-ready').write_text('ready')\n"
                    + "if operation=='delete': signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                    + "while True:\n"
                    + " if operation=='delete': (root/'cleanup-heartbeat').write_text(str(time.monotonic_ns()))\n"
                    + " time.sleep(0.02)\n"
                )
                cli.chmod(0o755)
                traps = "\n".join(
                    line
                    for line in (run.ROOT / "e2e/with-kube-gateway.sh")
                    .read_text()
                    .splitlines()
                    if line.startswith("trap ")
                )
                script = root / "harness.sh"
                script.write_text(
                    "cleanup() { :; }\n"
                    + traps
                    + "\necho 'probe starting'\n"
                    + f"{shlex.quote(sys.executable)} {shlex.quote(run.__file__)} --check\n"
                )
                parent = root / "parent.py"
                parent.write_text(
                    f"import sys\nsys.path.insert(0,{str(Path(run.__file__).parent)!r})\nimport run\n"
                    + "with run.termination_signals():\n"
                    + f" run.run(['bash',{str(script)!r}],timeout={0.7 if number is None else 30},termination_grace=0.5,log_path=__import__('pathlib').Path({str(root / 'harness.log')!r}))\n"
                )
                env = os.environ.copy()
                env.update(
                    OPENSHELL_BIN=str(cli),
                    OPENSHELL_E2E_KUBE_CONTEXT="fake-disposable",
                    OPENSHELL_E2E_KUBE_NAMESPACE="fake-gateway",
                    OPENSHELL_E2E_TRACING_EVIDENCE=str(root),
                    OPENSHELL_E2E_TRACING_NAMESPACE="fake-collector",
                    OPENSHELL_E2E_TRACING_GATEWAY="fake-gateway",
                )
                process = subprocess.Popen(
                    [sys.executable, str(parent)],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    wait_for(ready)
                    if number is not None:
                        os.kill(process.pid, number)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(
                        process.returncode,
                        1 if number is None else 128 + number,
                        stdout + stderr,
                    )
                    self.assertTrue(
                        heartbeat.exists(),
                        "the actual probe did not enter nested cleanup",
                    )
                    self.assert_child_stopped(heartbeat)
                    self.assertIn("probe starting", (root / "harness.log").read_text())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    for name in ["create-pid", "delete-pid"]:
                        stop_test_child(root / name)


if __name__ == "__main__":
    unittest.main()
