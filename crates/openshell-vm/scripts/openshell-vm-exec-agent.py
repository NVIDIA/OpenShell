#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import fcntl
import json
import os
import pty
import socket
import struct
import subprocess
import sys
import termios
import threading


PORT = 10777


def recv_line(sock_file):
    line = sock_file.readline()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def send_frame(sock_file, lock, frame):
    data = (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
    with lock:
        sock_file.write(data)
        sock_file.flush()


def validate_env(env_items):
    env = {}
    for item in env_items:
        if "=" not in item:
            raise ValueError(f"invalid env item: {item}")
        key, value = item.split("=", 1)
        if not key or not (key[0] == "_" or key[0].isalpha()):
            raise ValueError(f"invalid env key: {key}")
        if not all(ch == "_" or ch.isalnum() for ch in key):
            raise ValueError(f"invalid env key: {key}")
        env[key] = value
    return env


def set_winsize(fd, cols, rows):
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def stream_reader(pipe, frame_type, sock_file, lock):
    try:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                break
            send_frame(
                sock_file,
                lock,
                {"type": frame_type, "data": base64.b64encode(chunk).decode("ascii")},
            )
    finally:
        pipe.close()


def stdin_writer(proc, sock_file, sock, lock):
    """Forward stdin frames from the client to the subprocess.

    When the client sends ``stdin_close`` (or the connection drops), we
    close the subprocess's stdin pipe so it sees EOF.  We must NOT
    terminate the subprocess or shut down the socket here — the main
    thread needs the process to finish naturally and the stdout/stderr
    reader threads still need to flush their data back to the client.
    """
    try:
        while True:
            frame = recv_line(sock_file)
            if frame is None:
                break
            kind = frame.get("type")
            if kind == "stdin":
                payload = base64.b64decode(frame.get("data", ""))
                if proc.stdin is not None:
                    proc.stdin.write(payload)
                    proc.stdin.flush()
            elif kind == "stdin_close":
                break
            elif kind == "resize":
                pass
            else:
                send_frame(
                    sock_file,
                    lock,
                    {"type": "error", "message": f"unknown frame type: {kind}"},
                )
                break
    except BrokenPipeError:
        pass
    finally:
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass


def handle_client_pipe(conn, request, sock_file):
    """Handle a client connection using pipes (non-TTY mode)."""
    lock = threading.Lock()
    try:
        argv = request.get("argv") or ["sh"]
        cwd = request.get("cwd")
        env = os.environ.copy()
        env.update(validate_env(request.get("env") or []))

        proc = subprocess.Popen(
            argv,
            cwd=cwd or "/",
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout_thread = threading.Thread(
            target=stream_reader,
            args=(proc.stdout, "stdout", sock_file, lock),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stream_reader,
            args=(proc.stderr, "stderr", sock_file, lock),
            daemon=True,
        )
        stdin_thread = threading.Thread(
            target=stdin_writer, args=(proc, sock_file, conn, lock), daemon=True
        )

        stdout_thread.start()
        stderr_thread.start()
        stdin_thread.start()

        code = proc.wait()
        stdout_thread.join()
        stderr_thread.join()
        send_frame(sock_file, lock, {"type": "exit", "code": code})
    except Exception as exc:
        try:
            send_frame(sock_file, lock, {"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        try:
            sock_file.close()
        except Exception:
            pass
        conn.close()


def handle_client_tty(conn, request, sock_file):
    """Handle a client connection with PTY allocation."""
    lock = threading.Lock()
    master_fd = -1
    try:
        argv = request.get("argv") or ["sh"]
        cwd = request.get("cwd")
        env = os.environ.copy()
        env.update(validate_env(request.get("env") or []))
        env.setdefault("TERM", "xterm-256color")

        master_fd, slave_fd = pty.openpty()

        # Consume any resize frame sent right after the ExecRequest.
        # The host sends it before starting the stdin pump, so it
        # should arrive quickly. Use a short socket timeout.
        conn.settimeout(0.5)
        try:
            pending = sock_file.readline()
            if pending:
                frame = json.loads(pending.decode("utf-8"))
                if frame.get("type") == "resize":
                    set_winsize(
                        slave_fd,
                        frame.get("cols", 80),
                        frame.get("rows", 24),
                    )
        except (socket.timeout, ValueError, OSError):
            pass
        finally:
            conn.settimeout(None)

        proc = subprocess.Popen(
            argv,
            cwd=cwd or "/",
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid,
        )
        os.close(slave_fd)

        def pty_reader():
            try:
                while True:
                    try:
                        chunk = os.read(master_fd, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    send_frame(
                        sock_file,
                        lock,
                        {
                            "type": "stdout",
                            "data": base64.b64encode(chunk).decode("ascii"),
                        },
                    )
            except Exception:
                pass

        def pty_stdin_writer():
            try:
                while True:
                    frame = recv_line(sock_file)
                    if frame is None:
                        break
                    kind = frame.get("type")
                    if kind == "stdin":
                        payload = base64.b64decode(frame.get("data", ""))
                        try:
                            os.write(master_fd, payload)
                        except OSError:
                            break
                    elif kind == "resize":
                        try:
                            set_winsize(
                                master_fd,
                                frame.get("cols", 80),
                                frame.get("rows", 24),
                            )
                        except OSError:
                            pass
                    elif kind == "stdin_close":
                        break
                    else:
                        send_frame(
                            sock_file,
                            lock,
                            {"type": "error", "message": f"unknown frame type: {kind}"},
                        )
                        break
            except (BrokenPipeError, OSError):
                pass

        reader_thread = threading.Thread(target=pty_reader, daemon=True)
        stdin_thread = threading.Thread(target=pty_stdin_writer, daemon=True)
        reader_thread.start()
        stdin_thread.start()

        code = proc.wait()
        reader_thread.join(timeout=2)
        send_frame(sock_file, lock, {"type": "exit", "code": code})
    except Exception as exc:
        try:
            send_frame(sock_file, lock, {"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass
        try:
            sock_file.close()
        except Exception:
            pass
        conn.close()


def handle_client(conn):
    sock_file = conn.makefile("rwb", buffering=0)
    try:
        request = recv_line(sock_file)
        if request is None:
            sock_file.close()
            conn.close()
            return
    except Exception:
        sock_file.close()
        conn.close()
        return

    if request.get("tty"):
        handle_client_tty(conn, request, sock_file)
    else:
        handle_client_pipe(conn, request, sock_file)


def main():
    if not hasattr(socket, "AF_VSOCK"):
        print("AF_VSOCK is not available", file=sys.stderr)
        return 1

    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(16)

    while True:
        conn, _addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn,), daemon=True)
        thread.start()


if __name__ == "__main__":
    raise SystemExit(main())
