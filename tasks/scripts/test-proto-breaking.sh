#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check_script="$script_dir/check-proto-breaking.sh"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

mkdir -p "$work_dir/proto" "$work_dir/crates/openshell-server/proto"
cat > "$work_dir/buf.yaml" <<'EOF'
version: v2
modules:
  - path: proto
  - path: crates/openshell-server/proto
breaking:
  use:
    - FILE
EOF
cat > "$work_dir/proto/openshell.proto" <<'EOF'
syntax = "proto3";
package openshell.v1;
import "datamodel.proto";
message GetRequest { openshell.datamodel.v1.Resource resource = 1; }
service OpenShell { rpc Get(GetRequest) returns (GetRequest); }
EOF
cat > "$work_dir/proto/datamodel.proto" <<'EOF'
syntax = "proto3";
package openshell.datamodel.v1;
message Resource { string name = 1; }
EOF
cat > "$work_dir/proto/compute_driver.proto" <<'EOF'
syntax = "proto3";
package openshell.compute.v1;
message DriverRequest { string sandbox = 1; }
service ComputeDriver { rpc Start(DriverRequest) returns (DriverRequest); }
EOF
cat > "$work_dir/crates/openshell-server/proto/storage.proto" <<'EOF'
syntax = "proto3";
package openshell.storage.v1;
message StoredResource { string name = 1; }
EOF

git -C "$work_dir" init -q
git -C "$work_dir" add buf.yaml proto crates
git -C "$work_dir" -c user.name='OpenShell Test' -c user.email='test@example.invalid' commit -qm 'test: baseline protobuf descriptors'
base_sha=$(git -C "$work_dir" rev-parse HEAD)

run_check() {
  (cd "$work_dir" && PROTO_BREAKING_BASE_REF="$base_sha" "$check_script")
}

if (cd "$work_dir" && PROTO_BREAKING_BASE_REF= "$check_script") > "$work_dir/missing-base.log" 2>&1; then
  echo "Expected a missing baseline to fail closed." >&2
  exit 1
fi

# Additions to imported SDK descriptors are compatible.
cat > "$work_dir/proto/datamodel.proto" <<'EOF'
syntax = "proto3";
package openshell.datamodel.v1;
message Resource { string name = 1; string display_name = 2; }
EOF
run_check > "$work_dir/additive.log"

# A removed field in an imported descriptor must fail with a useful location.
cat > "$work_dir/proto/datamodel.proto" <<'EOF'
syntax = "proto3";
package openshell.datamodel.v1;
message Resource { string display_name = 2; }
EOF
if GITHUB_ACTIONS=true run_check > "$work_dir/breaking.log" 2>&1; then
  echo "Expected an imported protobuf field removal to fail." >&2
  exit 1
fi
if ! grep -q '^::error file=proto/datamodel.proto.*Previously present field "1"' "$work_dir/breaking.log"; then
  cat "$work_dir/breaking.log" >&2
  echo "Missing a diagnostic for the removed imported field." >&2
  exit 1
fi

# Extension protocol changes in the proto module must also be checked.
cat > "$work_dir/proto/datamodel.proto" <<'EOF'
syntax = "proto3";
package openshell.datamodel.v1;
message Resource { string name = 1; }
EOF
cat > "$work_dir/proto/compute_driver.proto" <<'EOF'
syntax = "proto3";
package openshell.compute.v1;
message DriverRequest { string renamed = 2; }
service ComputeDriver { rpc Start(DriverRequest) returns (DriverRequest); }
EOF
if GITHUB_ACTIONS=true run_check > "$work_dir/extension.log" 2>&1; then
  echo "Expected an extension protobuf field removal to fail." >&2
  exit 1
fi
if ! grep -q '^::error file=proto/compute_driver.proto.*Previously present field "1"' "$work_dir/extension.log"; then
  cat "$work_dir/extension.log" >&2
  echo "Missing a diagnostic for the removed extension field." >&2
  exit 1
fi

# A storage-only change is outside the proto module comparison.
cat > "$work_dir/proto/compute_driver.proto" <<'EOF'
syntax = "proto3";
package openshell.compute.v1;
message DriverRequest { string sandbox = 1; }
service ComputeDriver { rpc Start(DriverRequest) returns (DriverRequest); }
EOF
cat > "$work_dir/crates/openshell-server/proto/storage.proto" <<'EOF'
syntax = "proto3";
package openshell.storage.v1;
message StoredResource { string renamed = 2; }
EOF
run_check > "$work_dir/storage.log"

echo "Proto breaking checks passed: additive, SDK, extension, and storage-only cases."
