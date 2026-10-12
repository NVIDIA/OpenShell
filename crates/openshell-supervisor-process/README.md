# OpenShell process supervisor

This crate manages workload processes and SSH sessions through the admitted
isolation backend.

## Bounded streaming uploads

The CLI's built-in uploads use the `openshell-upload-v1` SSH subsystem. The
gateway relays its SSH channel without interpreting upload frames. The
supervisor launches the extractor through the ordinary `BoundaryExec` path,
with the same workload identity, environment, working directory, and
filesystem policy as other SSH children.

The upload protocol reserves stdout for control frames and the final result.
Extractor output is drained into bounded diagnostics. The supervisor grants a
1 MiB application window, and data frames carry at most 64 KiB. The CLI stops
sending archive data when outstanding bytes reach the window. A cumulative
acknowledgment returns credit only after `InputTask` successfully writes those
bytes through `BoundaryInput::write_all` and clears them from its in-flight
budget. The existing 4 MiB pending-input guard remains active.

The end frame carries the archive byte count and SHA-256 digest. A successful
result requires a matching stream, drained accepted writes, and a successful
extractor exit. Protocol failure, extractor failure, or channel cancellation
terminates the upload process and stops granting credit. Extraction writes
directly to the destination, so failures can leave partially extracted files;
the protocol does not provide rollback or atomic replacement.

The CLI requires supervisor support for this subsystem before sending archive
data. It does not fall back to the previous unpaced exec-stdin upload path.
Ordinary exec stdin and SFTP retain their existing input-budget behavior.
