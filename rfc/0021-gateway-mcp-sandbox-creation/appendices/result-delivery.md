# Appendix: Delivering a Child's Result

This appendix describes how a child agent's final result reaches its parent. It replaces the body's [Returning results](../README.md#returning-results) section.

## How it works

The parent agent uses three OpenShell MCP tools at `http://openshell.local/mcp`: `create_sandbox`, `wait` and `stop_sandbox`. The child writes its result to a file. When the parent calls `wait`, the gateway reads the file from the child's sandbox and returns it. The gateway keeps no copy.

The gateway is involved because the parent and child are isolated sandboxes, and the gateway is the only path between them: it already reaches every sandbox for `exec` and `get_file`, and it checks that the caller is the child's parent. This is the solution for now. Once OpenShell has sandbox-to-sandbox communication, a child can send its result to its parent directly.

### Step by step

**1. The parent creates the child.** The parent agent calls `create_sandbox` on `openshell.local/mcp`, with the child's command wrapped in `run-child`:

```text
create_sandbox { name: "worker", kind: "agent",
                 command: ["run-child", "codex", "exec", "<task>"] }
→ { handle: "worker" }
```

The parent's supervisor adds the sandbox token and the calling program and forwards the call. The gateway checks the grant, the limits and the policy ceiling, records the child under its parent and starts it.

**2. The child runs its agent.** In the child sandbox, `run-child` starts the command (here `codex exec`) with stdin closed. It saves the command's output to `/tmp/result.body` and its error output to `/tmp/result.err`. The child makes no calls to the gateway.

**3. The parent waits.** At the same time, the parent calls `wait`:

```text
wait { handle: "worker", until_file: "/tmp/result.txt", return_file: true, timeout_s: 45 }
```

The gateway checks that `worker` is the caller's own child. Then, while the child is READY, it runs `cat /tmp/result.txt` in the child every 3 seconds, through the same exec relay as `get_file`. While the file does not exist, `cat` fails and the gateway keeps waiting.

**4. The command ends, and `run-child` publishes the result.** It writes the exit status and then the output to `/tmp/result.txt.tmp`, and renames it to `/tmp/result.txt`. A rename is atomic, so `cat` never sees a half-written file. The first line is always `exit=N`; the rest is whatever the command printed, here a worker's answer in the benchmark's crash task:

```text
exit=0
{"errors": 102, "top_error": "cache unavailable"}
```

`run-child` publishes the file whether the command succeeded or failed. It then sleeps, keeping the child running for a collection window (one hour by default, `RUN_CHILD_LINGER_S`), so the file stays readable.

**5. `wait` returns the result.** The next `cat` succeeds. The gateway puts the file's bytes in the reply and keeps no copy:

```text
→ { file_ready: true, content: "exit=0\n{...}", truncated: false,
    phase: "SANDBOX_PHASE_READY", exit_code: null, timed_out: false }
```

If 45 seconds pass first, `wait` returns `timed_out: true` and the parent calls it again. If the child exits without publishing, `wait` returns `file_ready: false` with the child's exit code.

**6. The parent reads the status line.** `exit=0` means the rest of the content is the answer. Any other value means the command failed and the output may be partial; the parent reports the failure instead of using it.

**7. The parent stops the child.** It calls `stop_sandbox { handle: "worker" }`. The gateway deletes the child sandbox and its files, so the result exists only in the parent from now on.

## The contract

- **Complete or absent.** The result file is either fully written or not there.
- **Published even on failure.** Publication means the command finished, not that it succeeded; the first line says which.
- **Results must fit in 256 KiB.** `wait` and `get_file` return at most 256 KiB and report `truncated: true` beyond that. The status line comes first, so it is never cut.
- **Repeatable reads.** Reading does not change the file. A parent that lost a reply calls `wait` or `get_file` again and gets the same content.
- **Receive, then stop.** A stop sent while a read is in flight is a cancellation: the result can be lost.
- **No copy elsewhere.** Once the child is gone, its result is gone.
- **The result is untrusted.** The child writes its own result file, status line included, so a compromised child can fake it or carry prompt injection. The parent treats it as data from an untrusted agent.

## When things go wrong

| What happens | What the parent sees | What it should do |
|---|---|---|
| The command fails after partial output | `file_ready: true`, content starts `exit=4` | Report the failure; do not use the output as the answer |
| The result is over 256 KiB | `truncated: true`; the status line is intact | Use what it has; do not claim it is complete |
| The reply is lost or `wait` times out | `timed_out: true`, or no reply | Call `wait` again |
| The child never finishes | `timed_out: true` on every call | Give up after its own limit and stop the child |
| The sandbox crashes before publishing | `file_ready: false` and the sandbox's exit code | Report the failure; there is no result |
| The parent goes away | nothing | Deleting the parent removes the child; otherwise the window ends it |

## Interface

| Item | What it does |
|---|---|
| `wait.until_file` | An absolute path in the child. Keep waiting past READY until the file exists or the child exits; returns `file_ready`. |
| `wait.return_file` | With `until_file` only: include the file's `content` and `truncated`. Without `until_file` it is `INVALID_ARGUMENT`. |
| `get_file` | Reads a file from a running child, up to 256 KiB, and reports `truncated`. |
| `run-child` | A small wrapper for the child's command: closes stdin, publishes the result with its status line, stays running. The gateway does not depend on it; it returns the file's bytes whatever their format. |

## Evidence

The proof of concept ran nine delegation tasks with six harnesses (Pi, OpenCode, Qwen Code, Codex, Deep Agents and Hermes), three rounds each: 161 of 162 runs passed, and the one failure was the model provider's content filter. Checks without a model pass 26 of 26, including a failing command that publishes `exit=4` and repeated reads that return the same content. How to run the benchmark is in its [README](https://github.com/patkraw/OpenShell/blob/gateway-mcp-poc/examples/gateway-mcp-poc/bench/README.md), and the results are in its [report](https://github.com/patkraw/OpenShell/blob/gateway-mcp-poc/examples/gateway-mcp-poc/bench/REPORT.md).

## Open items

- **Collection window.** It is a `run-child` setting; a parent may want to set it at create time.
- **Shipping `run-child`.** Images carry their own copy today; OpenShell could ship it.
- **Larger results.** Outputs over 256 KiB need artifacts that outlive the child, which the RFC leaves to future work.
- **`wait` and harness timeouts.** Some harnesses end an MCP call after 60 seconds, so parents repeat 45-second waits.
