# OpenShell process supervisor

This crate manages workload processes and SSH sessions through the admitted
isolation backend.

## Program status

`program_status` scans PTY output of the canonical process and of SSH PTY
sessions for OSC 7501 program status reports. It keeps the protocol's
per-terminal records: ids, `clear`, dropping `working` and `blocked` at an OSC
133 `A` prompt, clearing every record on a full reset (RIS), and the record and
sequence limits. Reports, prompts, and resets apply in output order regardless
of how reads split them. A terminal's records end with its process. Report bytes are forwarded
unchanged; `msg` and `title` are validated and then discarded.

The supervisor answers the support query (`OSC 7501 ; ?`) itself by writing the
reply to the program's input, and removes the query from forwarded output.
Claude Code reports only when that reply arrives before the reply to the DA1
query it sends next. Only the bytes of a possible query are held back, and a
20 ms pause releases them.

A sandbox-wide summary takes the most active state across terminals
(working, then blocked, error, done, idle) and the latest client input, which
outlives the terminal that received it. Each gateway session receives the
summary at start, on every change, and within 15 seconds of new input, including
the last keystroke before typing stops. It also answers each
`WorkloadActivityRequest` with the current summary, which the gateway requires
before an idle stop. Every transition, including one undone within the same
read, restarts the state timer and advances a revision. Summaries are published
under the activity lock, so concurrent terminals never republish an older one.
Pushes and request replies take one ordering lock from snapshot to enqueue and
carry increasing sequence numbers, so the gateway can drop an older summary that
arrives late. Ages are relative, so supervisor and gateway clocks need
not agree.

## Bounded streaming uploads

The CLI's built-in uploads use the `openshell-upload-v1` SSH subsystem. Russh
returns SSH receive credit before the supervisor consumes channel data, so this
subsystem returns its own credit and uses SSH for everything else. The gateway
relays the channel without interpreting it.

The client sends one JSON plan line with the destination, then the raw tar
stream, then SSH EOF. When the plan arrives, the supervisor starts the
extractor through the ordinary `BoundaryExec` path, with the same workload
identity, environment, working directory and filesystem policy as other SSH
children. Startup runs inline, like an exec request.

Stdout carries only big-endian `u64` totals of archive bytes that `InputTask`
has written through `BoundaryInput::write_all`. The first total, zero, means
extraction started. Extractor stdout and stderr are both sent as SSH stderr,
so extractor output cannot forge credit. The client keeps at most 1 MiB beyond
the last total outstanding; the supervisor rejects input beyond that window.
The existing 4 MiB pending-input guard remains active.

After the extractor exits successfully and stdin has drained, the supervisor
sends the final total, then the exit status. The client succeeds only when the
status is zero and the final total equals the bytes it sent. A malformed plan,
credit violation, extended data or EOF before the plan fails the upload with
exit status 74. A rejection wins until the supervisor reports the exit result,
even after the extractor exits. Rejection, channel close or disconnect terminates the
extractor. Extraction writes directly to the destination, so failures can
leave partially extracted files; there is no rollback or atomic replacement.

The CLI requires supervisor support for this subsystem before sending archive
data. It does not fall back to the previous unpaced exec-stdin upload path.
Ordinary exec stdin and SFTP retain their existing input-budget behavior.
