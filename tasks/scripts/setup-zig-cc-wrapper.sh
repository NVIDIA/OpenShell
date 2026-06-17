#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "Usage: setup-zig-cc-wrapper.sh <cargo-target> <zig-target> <wrapper-dir>" >&2
}

if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

cargo_target=$1
zig_target=$2
wrapper_dir=$3

# cargo-zigbuild accepts Rust target triples with glibc suffixes, for example
# x86_64-unknown-linux-gnu.2.28. Zig's C/C++ driver expects the vendorless form.
zig_cc_target=${zig_target/-unknown-linux-/-linux-}

if [[ -n ${ZIG:-} ]]; then
  zig=$ZIG
elif command -v mise >/dev/null 2>&1; then
  zig=$(mise which zig)
else
  zig=$(command -v zig)
fi

mkdir -p "$wrapper_dir"

for tool in cc c++; do
  cat >"$wrapper_dir/$tool" <<EOF
#!/usr/bin/env bash
set -euo pipefail

args=()
skip_next=0
for arg in "\$@"; do
  if [[ \$skip_next -eq 1 ]]; then
    skip_next=0
    continue
  fi

  case "\$arg" in
    --target=*|-target=*)
      ;;
    --target|-target)
      skip_next=1
      ;;
    *)
      args+=("\$arg")
      ;;
  esac
done

exec "$zig" "$tool" --target="$zig_cc_target" "\${args[@]}"
EOF
  chmod +x "$wrapper_dir/$tool"
done

target_env=${cargo_target//[-.]/_}

if [[ -n ${GITHUB_ENV:-} ]]; then
  {
    echo "CC_${target_env}=$wrapper_dir/cc"
    echo "CXX_${target_env}=$wrapper_dir/c++"
  } >>"$GITHUB_ENV"
else
  echo "export CC_${target_env}=$wrapper_dir/cc"
  echo "export CXX_${target_env}=$wrapper_dir/c++"
fi
