# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""One OpenShell sandbox exposing a token-authenticated Jupyter API service."""

from __future__ import annotations

import importlib
import json
import os
import re
import secrets
import struct
import subprocess
import time
import uuid
import warnings
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

import yaml
from google.protobuf.json_format import ParseDict, ParseError

from openshell._proto import openshell_pb2, sandbox_pb2

if TYPE_CHECKING:
    from openshell import ExecResult, SandboxClient, SandboxSession

JUPYTER_PORT = 8888
JUPYTER_SERVICE = "jupyter"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_SERVICE_URL = re.compile(r"^\s*URL:\s+(\S+)\s*$", re.MULTILINE)
_START_JUPYTER = r"""
set -eu
umask 077
token_file=/tmp/openshell-jupyter-token
runtime_dir=/tmp/openshell-jupyter-runtime
mkdir -p "$runtime_dir"
IFS= read -r token
printf '%s' "$token" > "$token_file"
export HOME=/sandbox
export JUPYTER_RUNTIME_DIR="$runtime_dir"
export JUPYTER_TOKEN_FILE="$token_file"
nohup jupyter server \
  --ServerApp.ip=127.0.0.1 \
  --ServerApp.port=8888 \
  --ServerApp.port_retries=0 \
  --ServerApp.open_browser=False \
  --ServerApp.root_dir=/sandbox \
  --ServerApp.terminals_enabled=False \
  </dev/null >/tmp/openshell-jupyter.log 2>&1 &
""".strip()


class JupyterSandboxError(RuntimeError):
    """An OpenShell or Jupyter lifecycle operation failed."""


class JupyterExecutionError(JupyterSandboxError):
    """Code submitted to a Jupyter kernel failed."""


class JupyterSandbox(AbstractContextManager["JupyterSandbox"]):
    """Manage one sandbox, its Jupyter server, and its exposed service."""

    def __init__(
        self,
        *,
        client: SandboxClient,
        name: str,
        image: str | Path,
        policy: str | Path,
        openshell_bin: str = "openshell",
        cluster: str | None = None,
        ready_timeout: float = 60.0,
        execute_timeout: float = 60.0,
    ) -> None:
        if len(name) > 28 or not _NAME.fullmatch(name):
            raise ValueError(
                "name must be at most 28 lowercase letters, digits, or hyphens"
            )
        if ready_timeout <= 0 or execute_timeout <= 0:
            raise ValueError("timeouts must be greater than zero")

        policy_path = Path(policy).expanduser().resolve()
        if not policy_path.is_file():
            raise ValueError(f"policy does not exist: {policy_path}")

        image_reference = str(image)
        if Path(image_reference).expanduser().exists():
            raise ValueError(
                "the Python SDK requires an OCI image reference; build the "
                "Dockerfile before launching the fleet"
            )

        self.client = client
        self.name = name
        self.image = image_reference
        self.policy = policy_path
        self.openshell_bin = openshell_bin
        self.cluster = cluster
        self.ready_timeout = ready_timeout
        self.execute_timeout = execute_timeout
        self.service_url: str | None = None

        self._token = secrets.token_urlsafe(32)
        self._session: SandboxSession | None = None
        self._sandbox_create_attempted = False
        self._sandbox_created = False
        self._service_created = False

    def __enter__(self) -> JupyterSandbox:
        try:
            self._create_sandbox()
            self._start_jupyter()
            self.service_url = self._expose_service()
            self._wait_until_ready()
        except BaseException as error:
            cleanup_errors = self._cleanup()
            self._attach_cleanup_errors(error, cleanup_errors)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        cleanup_errors = self._cleanup()
        if not cleanup_errors:
            return False
        if exc_value is not None:
            self._attach_cleanup_errors(exc_value, cleanup_errors)
            return False
        raise BaseExceptionGroup(
            f"failed to clean up Jupyter sandbox {self.name}", cleanup_errors
        )

    def execute(self, code: str) -> str:
        """Execute code through the public Jupyter REST and WebSocket APIs."""
        if self.service_url is None:
            raise RuntimeError("sandbox is only available inside the context")

        kernel = self._request_json(
            "POST", "/api/kernels", {"name": "python3", "path": ""}
        )
        kernel_id = kernel.get("id")
        if not isinstance(kernel_id, str):
            raise JupyterSandboxError("Jupyter did not return a kernel id")

        execution_error: BaseException | None = None
        try:
            return self._execute_on_kernel(kernel_id, code)
        except BaseException as error:
            execution_error = error
            raise
        finally:
            try:
                self._request("DELETE", f"/api/kernels/{kernel_id}")
            except BaseException as error:
                if execution_error is None:
                    raise
                warnings.warn(
                    self._safe_message("failed to delete Jupyter kernel", error),
                    stacklevel=2,
                )

    def _create_sandbox(self) -> None:
        self._sandbox_create_attempted = True
        self._session = self.client.create_session(
            name=self.name,
            labels={"app": "jupyter", "managed-by": "jupyter-sandbox-example"},
            spec=self._sandbox_spec(),
        )
        self._sandbox_created = True
        self.client.wait_ready(self.name, timeout_seconds=self.ready_timeout)

    def _start_jupyter(self) -> None:
        self._exec(
            ["/bin/sh", "-c", _START_JUPYTER],
            stdin=f"{self._token}\n".encode(),
        )

    def _sandbox_spec(self) -> openshell_pb2.SandboxSpec:
        try:
            raw_policy = yaml.safe_load(self.policy.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise JupyterSandboxError(
                self._safe_message(f"could not load policy {self.policy}", error)
            ) from None
        if not isinstance(raw_policy, dict):
            raise JupyterSandboxError("sandbox policy must be a YAML mapping")

        # The canonical policy file calls this field `filesystem_policy`, while
        # the protobuf field is `filesystem`. The SDK does not yet expose the
        # CLI's canonical YAML loader, so normalize the one alias used here.
        policy_data = dict(raw_policy)
        filesystem = policy_data.pop("filesystem_policy", None)
        if filesystem is not None:
            policy_data["filesystem"] = filesystem
        try:
            policy = ParseDict(policy_data, sandbox_pb2.SandboxPolicy())
        except (ParseError, TypeError, ValueError) as error:
            raise JupyterSandboxError(
                self._safe_message(f"invalid sandbox policy {self.policy}", error)
            ) from None

        return openshell_pb2.SandboxSpec(
            template=openshell_pb2.SandboxTemplate(image=self.image),
            policy=policy,
            providers=[],
        )

    def _expose_service(self) -> str:
        completed = self._run_service(
            "service",
            "expose",
            self.name,
            str(JUPYTER_PORT),
            JUPYTER_SERVICE,
            capture=True,
        )
        self._service_created = True
        output = _ANSI_ESCAPE.sub("", completed.stdout or "")
        match = _SERVICE_URL.search(output)
        if match is None:
            raise JupyterSandboxError(
                "OpenShell exposed the service but did not return its URL"
            )

        service_url = match.group(1).rstrip("/")
        parsed = urlsplit(service_url)
        host = parsed.hostname or ""
        local_host = host in {"127.0.0.1", "::1", "localhost"} or host.endswith(
            ".localhost"
        )
        if parsed.scheme not in {"http", "https"} or not local_host:
            raise JupyterSandboxError(
                "this example supports services exposed by a local gateway only"
            )
        return service_url

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self.ready_timeout
        while time.monotonic() < deadline:
            try:
                self._request("GET", "/api/status")
                return
            except (HTTPError, URLError, TimeoutError, JupyterSandboxError):
                time.sleep(1)

        logs = self._jupyter_logs()
        detail = f"\nJupyter log:\n{logs}" if logs else ""
        raise JupyterSandboxError(
            f"Jupyter in sandbox {self.name} was not ready after "
            f"{self.ready_timeout:g} seconds{detail}"
        )

    def _jupyter_logs(self) -> str:
        try:
            result = self._exec(
                [
                    "/bin/sh",
                    "-c",
                    "tail -n 40 /tmp/openshell-jupyter.log 2>/dev/null || true",
                ]
            )
        except JupyterSandboxError:
            return ""
        return self._redact(result.stdout).strip()

    def _execute_on_kernel(self, kernel_id: str, code: str) -> str:
        try:
            websocket = importlib.import_module("websocket")
        except ImportError as error:
            raise JupyterSandboxError(
                "websocket-client is required; install the example dependencies"
            ) from error

        session_id = uuid.uuid4().hex
        msg_id = uuid.uuid4().hex
        channels_url = self._api_url(f"/api/kernels/{kernel_id}/channels")
        channels_url = self._with_query(channels_url, session_id=session_id)
        parsed = urlsplit(channels_url)
        host = parsed.hostname or "localhost"
        ws_url = urlunsplit(
            (
                "wss" if parsed.scheme == "https" else "ws",
                parsed.netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

        try:
            socket = websocket.create_connection(
                ws_url,
                http_no_proxy=[host],
                suppress_origin=True,
                timeout=min(5.0, self.execute_timeout),
            )
        except BaseException as error:
            raise JupyterSandboxError(
                self._safe_message("could not open Jupyter kernel channels", error)
            ) from None

        request = {
            "channel": "shell",
            "header": {
                "date": datetime.now(UTC).isoformat(),
                "msg_id": msg_id,
                "msg_type": "execute_request",
                "session": session_id,
                "username": "openshell",
                "version": "5.3",
            },
            "parent_header": {},
            "metadata": {},
            "content": {
                "allow_stdin": False,
                "code": code,
                "silent": False,
                "stop_on_error": True,
                "store_history": True,
                "user_expressions": {},
            },
        }

        output: list[str] = []
        error_text: str | None = None
        idle = False
        replied = False
        deadline = time.monotonic() + self.execute_timeout
        try:
            socket.send(json.dumps(request))
            while not (idle and replied):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise JupyterSandboxError(
                        f"execution timed out after {self.execute_timeout:g} seconds"
                    )
                socket.settimeout(min(1.0, remaining))
                try:
                    message = self._decode_message(socket.recv())
                except websocket.WebSocketTimeoutException:
                    continue

                parent = message.get("parent_header", {})
                if parent.get("msg_id") != msg_id:
                    continue
                header = message.get("header", {})
                msg_type = header.get("msg_type")
                content = message.get("content", {})

                if msg_type == "stream":
                    output.append(str(content.get("text", "")))
                elif msg_type in {"display_data", "execute_result"}:
                    data = content.get("data", {})
                    if "text/plain" in data:
                        output.append(str(data["text/plain"]))
                elif msg_type == "error":
                    error_text = self._format_kernel_error(content)
                elif msg_type == "execute_reply":
                    replied = True
                    if content.get("status") == "error" and error_text is None:
                        error_text = self._format_kernel_error(content)
                elif msg_type == "status" and content.get("execution_state") == "idle":
                    idle = True
        except JupyterSandboxError:
            raise
        except BaseException as error:
            raise JupyterSandboxError(
                self._safe_message("Jupyter kernel communication failed", error)
            ) from None
        finally:
            socket.close()

        if error_text is not None:
            raise JupyterExecutionError(error_text)
        return "".join(output)

    @staticmethod
    def _decode_message(payload: str | bytes) -> dict[str, Any]:
        if isinstance(payload, str):
            decoded = json.loads(payload)
        else:
            if len(payload) < 8:
                raise JupyterSandboxError("received an invalid binary Jupyter message")
            offset_count = struct.unpack_from("!I", payload)[0]
            table_size = 4 * (offset_count + 1)
            if offset_count < 1 or len(payload) < table_size:
                raise JupyterSandboxError("received an invalid binary Jupyter message")
            offsets = struct.unpack_from(f"!{offset_count}I", payload, 4)
            start = offsets[0]
            end = offsets[1] if offset_count > 1 else len(payload)
            if start < table_size or end < start or end > len(payload):
                raise JupyterSandboxError("received an invalid binary Jupyter message")
            decoded = json.loads(payload[start:end])
        if not isinstance(decoded, dict):
            raise JupyterSandboxError("received an invalid Jupyter message")
        return decoded

    @staticmethod
    def _format_kernel_error(content: dict[str, Any]) -> str:
        traceback = content.get("traceback")
        if isinstance(traceback, list) and traceback:
            return _ANSI_ESCAPE.sub("", "\n".join(map(str, traceback)))
        name = str(content.get("ename", "Error"))
        value = str(content.get("evalue", ""))
        return f"{name}: {value}".rstrip()

    def _request_json(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = self._request(method, path, payload)
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise JupyterSandboxError("Jupyter returned an unexpected response")
        return decoded

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> bytes:
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            self._api_url(path),
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
                return response.read()
        except HTTPError as error:
            detail = self._redact(error.read().decode(errors="replace")).strip()
            suffix = f": {detail}" if detail else ""
            raise JupyterSandboxError(
                f"Jupyter API {method} {path} returned HTTP {error.code}{suffix}"
            ) from None
        except URLError as error:
            raise JupyterSandboxError(
                self._safe_message(f"Jupyter API {method} {path} failed", error)
            ) from None

    def _api_url(self, path: str) -> str:
        if self.service_url is None:
            raise RuntimeError("sandbox is only available inside the context")
        base = self.service_url.rstrip("/")
        return self._with_query(f"{base}/{path.lstrip('/')}")

    def _with_query(self, url: str, **extra: str) -> str:
        parsed = urlsplit(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query["token"] = self._token
        query.update(extra)
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(query),
                parsed.fragment,
            )
        )

    def _cleanup(self) -> list[BaseException]:
        errors: list[BaseException] = []
        if self._service_created:
            try:
                self._run_service(
                    "service",
                    "delete",
                    self.name,
                    JUPYTER_SERVICE,
                    capture=True,
                )
            except BaseException as error:
                errors.append(error)
            finally:
                self._service_created = False
                self.service_url = None

        if self._sandbox_create_attempted or self._sandbox_created:
            try:
                deleted = self.client.delete(self.name)
                if deleted:
                    self.client.wait_deleted(
                        self.name, timeout_seconds=self.ready_timeout
                    )
            except BaseException as error:
                if "not found" not in str(error).lower():
                    errors.append(error)
            finally:
                self._session = None
                self._sandbox_create_attempted = False
                self._sandbox_created = False
        return errors

    @staticmethod
    def _attach_cleanup_errors(
        original: BaseException, cleanup_errors: list[BaseException]
    ) -> None:
        for error in cleanup_errors:
            note = f"cleanup also failed: {JupyterSandbox._error_text(error)}"
            if hasattr(original, "add_note"):
                original.add_note(note)
            warnings.warn(note, stacklevel=3)

    def _exec(
        self,
        command: list[str],
        *,
        stdin: bytes | None = None,
    ) -> ExecResult:
        if self._session is None:
            raise RuntimeError("sandbox is only available inside the context")
        result = self._session.exec(
            command,
            stdin=stdin,
            timeout_seconds=max(1, round(self.ready_timeout)),
        )
        if result.exit_code != 0:
            detail = self._redact(result.stderr or result.stdout).strip()
            suffix = f": {detail}" if detail else ""
            raise JupyterSandboxError(
                f"sandbox command failed ({result.exit_code}): "
                f"{' '.join(command)}{suffix}"
            )
        return result

    def _run_service(
        self,
        *args: str,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [self.openshell_bin, *args]
        environment = os.environ.copy()
        if self.cluster is not None:
            environment["OPENSHELL_GATEWAY"] = self.cluster
        completed = subprocess.run(
            command,
            check=False,
            env=environment,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        if completed.returncode != 0:
            detail = self._redact(completed.stderr or completed.stdout or "").strip()
            suffix = f": {detail}" if detail else ""
            raise JupyterSandboxError(
                f"OpenShell command failed ({completed.returncode}): "
                f"{' '.join(command)}{suffix}"
            )
        return completed

    def _redact(self, value: str) -> str:
        value = value.replace(self._token, "<redacted>")
        return re.sub(r"([?&]token=)[^&\s]+", r"\1<redacted>", value)

    def _safe_message(self, prefix: str, error: BaseException) -> str:
        return f"{prefix}: {self._redact(self._error_text(error))}"

    @staticmethod
    def _error_text(error: BaseException) -> str:
        return str(error) or type(error).__name__
