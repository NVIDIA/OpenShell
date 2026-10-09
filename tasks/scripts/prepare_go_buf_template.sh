#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

prepare_go_buf_template() {
  local sdk_root=$1
  local work_dir=$2
  local output_dir=$work_dir
  local template=$work_dir/buf.gen.yaml

  if command -v cygpath &>/dev/null; then
    output_dir=$(cygpath -m "$work_dir")
  fi
  local sed_output_dir=${output_dir//&/\\&}
  sed "s|out: sdk/go|out: $sed_output_dir|" "$sdk_root/buf.gen.yaml" >"$template"

  if command -v cygpath &>/dev/null; then
    local go_plugin grpc_plugin
    go_plugin=$(cygpath -m "$(command -v protoc-gen-go)")
    grpc_plugin=$(cygpath -m "$(command -v protoc-gen-go-grpc)")
    go_plugin=${go_plugin//&/\\&}
    grpc_plugin=${grpc_plugin//&/\\&}
    sed \
      -e "s|local: protoc-gen-go$|local: $go_plugin|" \
      -e "s|local: protoc-gen-go-grpc$|local: $grpc_plugin|" \
      "$template" >"$work_dir/buf.gen.windows.yaml"
    mv "$work_dir/buf.gen.windows.yaml" "$template"
  fi

  printf '%s\n' "$template"
}
