// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export * from './gen/datamodel_pb.js';
// Advanced surface: the full generated protobuf types (messages, enums, and the
// OpenShell service descriptor) for callers using the raw escape hatch on
// OpenShellClient / SandboxClient (`.raw` and `.transport`). These are the
// uncurated wire types; import them from '@nvidia/openshell-sdk/raw'. The
// curated entry point stays free of generated types so its surface does not
// shift when the proto regenerates. The four generated modules export disjoint
// symbol names, so a flat re-export is unambiguous.
export * from './gen/openshell_pb.js';
export * from './gen/options_pb.js';
export * from './gen/sandbox_pb.js';
