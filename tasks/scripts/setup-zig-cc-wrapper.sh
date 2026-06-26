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

bare_cargo_target=$cargo_target
if [[ $bare_cargo_target =~ ^(.+)\.[0-9]+\.[0-9]+$ ]]; then
  bare_cargo_target=${BASH_REMATCH[1]}
fi

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

cat >"$wrapper_dir/ar" <<EOF
#!/usr/bin/env bash
set -euo pipefail

exec "$zig" ar "\$@"
EOF
chmod +x "$wrapper_dir/ar"

cat >"$wrapper_dir/ranlib" <<EOF
#!/usr/bin/env bash
set -euo pipefail

exec "$zig" ranlib "\$@"
EOF
chmod +x "$wrapper_dir/ranlib"

processor=${cargo_target%%-*}
toolchain_file="$wrapper_dir/toolchain.cmake"
cat >"$toolchain_file" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR "$processor")
set(CMAKE_C_COMPILER "$wrapper_dir/cc")
set(CMAKE_CXX_COMPILER "$wrapper_dir/c++")
set(CMAKE_AR "$wrapper_dir/ar")
set(CMAKE_RANLIB "$wrapper_dir/ranlib")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
EOF

is_stale_z3_build_dir() {
  local build_dir=$1

  grep -R -q -E \
    'cargo-zigbuild|zigc(c|xx)-.*unknown-linux-gnu\.[0-9]+\.[0-9]+' \
    "$build_dir/CMakeCache.txt" "$build_dir/CMakeFiles" 2>/dev/null
}

for profile in release debug; do
  z3_build_root="target/$bare_cargo_target/$profile/build"
  if [[ -d $z3_build_root ]]; then
    while IFS= read -r z3_build_dir; do
      if is_stale_z3_build_dir "$z3_build_dir"; then
        echo "Removing stale z3-sys CMake cache: $z3_build_dir" >&2
        rm -rf "$z3_build_dir"
      fi
    done < <(find "$z3_build_root" -mindepth 3 -maxdepth 3 -type d -path "*/z3-sys-*/out/build")
  fi
done

target_env=${cargo_target//[-.]/_}
bare_target_env=${bare_cargo_target//[-.]/_}

if [[ -n ${GITHUB_ENV:-} ]]; then
  {
    echo "CC_${target_env}=$wrapper_dir/cc"
    echo "CXX_${target_env}=$wrapper_dir/c++"
    echo "AR_${target_env}=$wrapper_dir/ar"
    echo "RANLIB_${target_env}=$wrapper_dir/ranlib"
    echo "CMAKE_TOOLCHAIN_FILE_${target_env}=$toolchain_file"
    if [[ $bare_target_env != "$target_env" ]]; then
      echo "CC_${bare_target_env}=$wrapper_dir/cc"
      echo "CXX_${bare_target_env}=$wrapper_dir/c++"
      echo "AR_${bare_target_env}=$wrapper_dir/ar"
      echo "RANLIB_${bare_target_env}=$wrapper_dir/ranlib"
      echo "CMAKE_TOOLCHAIN_FILE_${bare_target_env}=$toolchain_file"
    fi
  } >>"$GITHUB_ENV"
else
  echo "export CC_${target_env}=$wrapper_dir/cc"
  echo "export CXX_${target_env}=$wrapper_dir/c++"
  echo "export AR_${target_env}=$wrapper_dir/ar"
  echo "export RANLIB_${target_env}=$wrapper_dir/ranlib"
  echo "export CMAKE_TOOLCHAIN_FILE_${target_env}=$toolchain_file"
  if [[ $bare_target_env != "$target_env" ]]; then
    echo "export CC_${bare_target_env}=$wrapper_dir/cc"
    echo "export CXX_${bare_target_env}=$wrapper_dir/c++"
    echo "export AR_${bare_target_env}=$wrapper_dir/ar"
    echo "export RANLIB_${bare_target_env}=$wrapper_dir/ranlib"
    echo "export CMAKE_TOOLCHAIN_FILE_${bare_target_env}=$toolchain_file"
  fi
fi
