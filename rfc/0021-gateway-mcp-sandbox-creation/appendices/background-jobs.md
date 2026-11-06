# Appendix: Background Jobs

> This is an appendix to the [RFC](../README.md). Please familiarize yourself with the RFC before reading this.

This appendix describes how background jobs run inside a child and how a
parent holds a conversation with a harness over several jobs. The RFC's
[Running work and collecting results](../README.md#running-work-and-collecting-results)
section gives the rules; this page gives the details.

## Follow-up turns

A harness saves its conversation to a file inside the child, and a later
process can resume it. Each turn is a new background job in the same working
directory. The parent asks for structured output, keeps the harness's
conversation id from the result, and passes it to the next turn. OpenShell
never reads or stores conversation ids.

```text
exec {name: "worker", background: true, workdir: "/sandbox/work",
      command: ["claude", "-p", "--output-format", "json", "Plan the change"]}
→ job: 1-0c4e9a12
wait {name: "worker", job: "1-0c4e9a12"}
→ completed · exit 0 · stdout: {"session_id": "...", "result": "the plan", ...}
exec {name: "worker", background: true, workdir: "/sandbox/work",
      command: ["claude", "-p", "--resume", "<session_id>",
                "--output-format", "json", "Make it work offline"]}
```

The parent uses the id rather than "continue the last conversation", which
would pick the wrong one if a child ever held two. A child cannot ask its
parent anything while a job runs: a child that needs input ends its turn with
the question, and the parent answers in the next turn. An exit code of 0 does
not prove the task succeeded, so the parent also checks the harness's own
error fields. If structured output is truncated, it cannot be parsed and the
conversation id may be lost; this is a known limit of this version.

## How jobs work

Every step is a short `exec` that runs a fixed script built into the gateway.
The caller's command reaches the script as separate arguments, quoted like any
`exec` argument, and runs as `"$@"`; it is never pasted into the script's
text. To start a job, the script claims the next job number by creating
`/tmp/openshell/jobs/<n>/`, which succeeds for exactly one of two starts
racing each other. It starts the command detached (in its own session where
`setsid` exists), with stdin read from a file and stdout and stderr written to
files, so the starting `exec` returns at once while the job keeps running. The
job records its own process id and start time, and writes its exit code to a
temporary file that is then renamed, so an exit file always holds a complete
code.

`wait` reads the job's state with short `exec` calls, every two seconds and
within its own limit:

- **completed:** the exit file exists. `wait` returns the exit code and the
  first and last 16 KiB of each output stream, as `exec` does.
- **running:** the recorded process is alive and has the recorded start time,
  so a reused process id is not mistaken for the job. A job folder whose
  process id has not been written yet counts as running for 10 seconds.
- **lost:** neither, for example because the job was killed or the child
  restarted. `wait` says so instead of waiting forever.

## Output

`wait` reports only the state until the job completes. To watch progress, the
parent can run `tail` on the job's output file with a foreground `exec`. Empty
output does not mean the job is stuck: a harness in one-shot JSON mode may
print nothing until its turn ends.

The gateway checks a job id's form before using it, so an id cannot point
outside the jobs folder. Output files can grow inside the child, and a job
that writes a lot can fill the child's disk. The child writes these files, so
the parent receives their contents as data from the child, not as facts the
gateway has checked.

## One job at a time

A job that has completed or is `lost` no longer counts toward the one-job
limit. A job's result can be read until the next job starts in that child;
starting one removes the folders of earlier jobs. Parallel work uses more
children, which keeps tasks from overwriting each other's files and keeps two
turns of one harness conversation from running at once. Processes that a job
starts itself are part of that job.

## Requirements

Jobs need `sh`, `/proc` and `stat` in the child and a writable `/tmp`. A child
takes its filesystem rules from its parent's policy, so a parent whose policy
does not let `/tmp` be written has children that cannot run jobs; starting one
is refused with that reason before anything is claimed. The default policy
allows it. A native detach option on `ExecSandbox`, handled by the sandbox
runtime, can replace the script later.
