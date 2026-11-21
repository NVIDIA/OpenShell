# OpenShell process supervisor

This crate manages workload processes and SSH sessions through the admitted
isolation backend.

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

## Terminal attachments to a TTY main process

The supervisor retains up to 1 MiB of the main process's output and replays it
to each new `openshell-main` attachment. For a TTY main process, those bytes
are escape sequences written for whichever terminal was attached when they
were produced, so a PTY attachment adapts the replay instead of copying it:

- Before the replay, it restores the modes in effect where the retained window
  starts, such as the alternate screen, cursor visibility, mouse reporting,
  bracketed paste, keypad, and keyboard protocols. `TerminalState` builds them
  from evicted output.
- It drops terminal queries from the replay. The program already received or
  gave up on those answers; a new terminal would type them into its stdin.
- After the replay, it resets scroll margins set for an earlier terminal size.
- It resizes the PTY through an interim size, as `kubectl attach` does, so the
  program redraws even when the attachment matches the current size.
- When the attachment detaches, falls behind, or the process exits, it resets
  the client's terminal modes and leaves the alternate screen.

Clients without a PTY still receive the raw retained bytes.
