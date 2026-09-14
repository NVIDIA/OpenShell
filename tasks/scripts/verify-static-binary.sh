#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Verify a binary is a genuine, complete, fully static executable.
#
# The supervisor is executed from inside arbitrary sandbox images (Docker
# extraction, Podman image volumes, the Kubernetes copy-self path), so any
# dynamic linkage breaks it on musl-based images and on images whose glibc is
# older than the build host's. Both supported supervisor libc variants (musl
# and glibc-static) must therefore produce a static binary.
#
# This check exists because the failure is silent: `zig cc` accepts `-static`
# for `*-linux-gnu` targets and emits a dynamically linked binary anyway, so a
# toolchain change can quietly downgrade linkage without failing the build.
#
# The verifier must also fail closed on malformed input; readelf can exit 0 on a
# damaged ELF, which naive parsing would read as "no interpreter, no
# dependencies". The checks below therefore require, for each binary:
#   * an executable ELF: ET_EXEC (classic static) or ET_DYN (static-PIE);
#   * a fully readable ELF header, program header table, and dynamic section
#     (readelf must exit 0 AND emit no diagnostics — see readelf_strict);
#   * at least one PT_LOAD segment, every PT_LOAD contained within the file
#     (catches truncation that readelf does not otherwise report);
#   * no PT_INTERP and no DT_NEEDED (the actual static-linkage properties);
#   * for ET_DYN, the DF_1_PIE flag, which a static-PIE executable sets and a
#     shared library does not.
#
# Accepts both classic static and static-PIE binaries. static-PIE keeps a
# PT_DYNAMIC segment for self-relocation, so linkage is judged by the absence of
# PT_INTERP and DT_NEEDED, not by the absence of a dynamic section.

usage() {
  echo "Usage: verify-static-binary.sh <binary> [binary ...]" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

# Resolve a readelf-compatible inspector. macOS ships none of these; Homebrew
# binutils provides `greadelf` and LLVM provides `llvm-readelf`, both of which
# emit GNU-style output this script parses. Prefer GNU readelf, then greadelf,
# then llvm-readelf.
READELF=""
for candidate in readelf greadelf llvm-readelf; do
  if command -v "$candidate" >/dev/null 2>&1; then
    READELF=$candidate
    break
  fi
done

if [[ -z $READELF ]]; then
  host_os=""
  command -v uname >/dev/null 2>&1 && host_os=$(uname -s 2>/dev/null || true)
  # Skip only on a host positively identified as non-Linux — e.g. a macOS dev
  # cross-building the Linux supervisor via cargo-zigbuild, where mise installs
  # no binutils. Linux (including CI), or any host whose OS cannot be determined,
  # fails closed so a missing inspector never silently passes. Static linkage is
  # still enforced in CI, which runs on Linux.
  if [[ "$host_os" == "Linux" || -z $host_os ]]; then
    echo "error: readelf (or greadelf/llvm-readelf) is required to inspect binary linkage" >&2
    exit 2
  fi
  echo "warning: no readelf/greadelf/llvm-readelf found on ${host_os}; skipping static-linkage verification." >&2
  echo "         install GNU binutils (greadelf) or LLVM (llvm-readelf) to verify locally; CI enforces it on Linux." >&2
  exit 0
fi

# Explicit template: BSD/macOS mktemp requires one, GNU mktemp accepts it.
readelf_err=$(mktemp "${TMPDIR:-/tmp}/verify-static-binary.XXXXXXXX")
trap 'rm -f "$readelf_err"' EXIT

# Run readelf and print its stdout. Fails (returns non-zero) if readelf exits
# non-zero OR writes anything to stderr, leaving the diagnostics in
# $readelf_err. readelf reports a truncated or corrupt ELF on stderr while still
# exiting 0, so the stderr check — not the exit code — is what makes a damaged
# file fail closed instead of reading as "no PT_INTERP, no DT_NEEDED".
readelf_strict() {
  local out
  out=$("$READELF" "$@" 2>"$readelf_err") || return 1
  [[ -s "$readelf_err" ]] && return 1
  printf '%s\n' "$out"
  return 0
}

failed=0

for binary in "$@"; do
  if [[ ! -f $binary ]]; then
    echo "error: binary not found: $binary" >&2
    failed=1
    continue
  fi

  echo "==> Inspecting $binary"

  # llvm-readelf rejects the `--` end-of-options marker that GNU readelf accepts,
  # so make a leading-dash path safe for either tool by prefixing "./" instead.
  case "$binary" in
    -*) scan_path="./$binary" ;;
    *) scan_path="$binary" ;;
  esac

  if command -v file >/dev/null 2>&1; then
    file "$scan_path" || true
  fi

  # The ELF header and the full program header table must be readable. A
  # truncated or non-ELF file makes readelf emit a diagnostic, which fails here
  # instead of being misread as a static binary.
  if ! headers=$(readelf_strict --wide --file-header --program-headers "$scan_path"); then
    echo "error: $binary: unable to read a complete ELF (truncated, malformed, or not an ELF)" >&2
    sed 's/^/  /' "$readelf_err" >&2 || true
    failed=1
    continue
  fi

  if grep -Eq '^[[:space:]]*Type:[[:space:]]+EXEC' <<<"$headers"; then
    elf_type=EXEC
  elif grep -Eq '^[[:space:]]*Type:[[:space:]]+DYN' <<<"$headers"; then
    elf_type=DYN
  else
    echo "error: $binary is not an executable ELF (expected ET_EXEC or ET_DYN)" >&2
    failed=1
    continue
  fi

  # Every runnable ELF has at least one PT_LOAD segment. Its absence means the
  # program header table was truncated or the input is not a program image.
  if ! grep -qw 'LOAD' <<<"$headers"; then
    echo "error: $binary has no PT_LOAD segment; it is truncated or not an executable" >&2
    failed=1
    continue
  fi

  # Every PT_LOAD must lie within the file. readelf can exit 0 with empty stderr
  # on a file whose section headers were stripped even though a LOAD segment runs
  # past EOF, so validate p_offset + p_filesz <= file size explicitly rather than
  # trusting readelf to notice the truncation.
  # wc -c is portable (GNU stat -c / BSD stat -f differ); arithmetic strips any
  # leading whitespace BSD wc prints. The redirect also tolerates a '-' path.
  file_size=$(( $(wc -c < "$binary") ))
  load_past_eof=0
  while read -r ph_type ph_off _ph_va _ph_pa ph_fsize _ph_rest; do
    [[ "$ph_type" == "LOAD" ]] || continue
    # ph_off and ph_fsize are hex (e.g. 0x6a8440); bash arithmetic parses 0x.
    if (( ph_off + ph_fsize > file_size )); then
      echo "error: $binary: PT_LOAD at ${ph_off} (filesz ${ph_fsize}) extends past end of file (${file_size} bytes); it is truncated" >&2
      load_past_eof=1
    fi
  done <<<"$headers"
  if (( load_past_eof )); then
    failed=1
    continue
  fi

  if grep -qw 'INTERP' <<<"$headers"; then
    echo "error: $binary has a program interpreter (PT_INTERP); it is dynamically linked" >&2
    grep -w -A1 'INTERP' <<<"$headers" >&2 || true
    failed=1
    continue
  fi

  # The dynamic section must also be fully readable. A classic static binary has
  # none (readelf says so on stdout and exits cleanly, with no stderr); a
  # static-PIE has one without any DT_NEEDED entries.
  if ! dynamic=$(readelf_strict --wide --dynamic "$scan_path"); then
    echo "error: $binary: unable to read the ELF dynamic section (truncated or malformed)" >&2
    sed 's/^/  /' "$readelf_err" >&2 || true
    failed=1
    continue
  fi

  # Anchor the dynamic table to PT_DYNAMIC. GNU readelf --dynamic reads the
  # SHT_DYNAMIC *section*, whose file offset can be pointed away from the real
  # PT_DYNAMIC *segment* to hide DT_NEEDED entries (llvm-readelf warns on this;
  # GNU does not). Require the section offset readelf used to match the
  # PT_DYNAMIC segment offset from the program headers; fail closed on any
  # disagreement. Compare numerically so 0x0b1da8 and 0xb1da8 are equal.
  dyn_seg_off=$(awk '$1 == "DYNAMIC" { print $2; exit }' <<<"$headers")
  dyn_sec_off=$(grep -oE 'Dynamic section at offset 0x[0-9a-fA-F]+' <<<"$dynamic" | grep -oE '0x[0-9a-fA-F]+' | head -1 || true)
  if [[ -n $dyn_seg_off || -n $dyn_sec_off ]]; then
    if [[ -z $dyn_seg_off || -z $dyn_sec_off ]] || (( dyn_seg_off != dyn_sec_off )); then
      echo "error: $binary: dynamic table location mismatch (PT_DYNAMIC ${dyn_seg_off:-none}, section ${dyn_sec_off:-none}); malformed or tampered" >&2
      failed=1
      continue
    fi
  fi

  if grep -qw 'NEEDED' <<<"$dynamic"; then
    echo "error: $binary depends on shared libraries (DT_NEEDED); it is dynamically linked" >&2
    grep -w 'NEEDED' <<<"$dynamic" >&2 || true
    failed=1
    continue
  fi

  # An ET_DYN static-PIE executable sets DT_FLAGS_1 DF_1_PIE; a shared library
  # (also ET_DYN, and possibly without PT_INTERP/DT_NEEDED) does not. Require the
  # flag so a .so cannot pass as a static executable.
  if [[ "$elf_type" == "DYN" ]] && ! grep -E '\(FLAGS_1\)' <<<"$dynamic" | grep -qw 'PIE'; then
    echo "error: $binary is an ET_DYN object without DF_1_PIE; it looks like a shared library, not a static-PIE executable" >&2
    failed=1
    continue
  fi

  echo "statically linked: no PT_INTERP, no DT_NEEDED"
done

exit "$failed"
