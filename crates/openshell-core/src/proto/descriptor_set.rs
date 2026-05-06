// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded protobuf `FileDescriptorSet` for gRPC server reflection.
//!
//! This blob covers **`OpenShell`** protos only. The gateway reflection service also registers
//! `grpc.health.v1` and `grpc.reflection.v1` using the embedded sets exported by the
//! `tonic-health` and `tonic-reflection` crates (`tonic_health::pb::FILE_DESCRIPTOR_SET` and the
//! set `tonic_reflection::server::Builder::build_v1()` adds by default).

/// Serialized `FileDescriptorSet` covering `OpenShell` gateway protos (see `build.rs`).
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/openshell_file_descriptor_set.bin"
));
