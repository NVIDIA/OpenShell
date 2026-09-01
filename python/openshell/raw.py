# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated OpenShell gRPC surface for advanced SDK use.

The modules exported here contain the uncurated protobuf wire types. Prefer the
high-level SDK where it has a suitable method; use this module with
``SandboxClient.raw`` when the gateway RPC has not received a curated wrapper.
"""

from ._proto import (
    datamodel_pb2,
    inference_pb2,
    openshell_pb2,
    options_pb2,
    sandbox_pb2,
)
from ._proto.inference_pb2_grpc import InferenceStub
from ._proto.openshell_pb2_grpc import OpenShellStub

__all__ = [
    "InferenceStub",
    "OpenShellStub",
    "datamodel_pb2",
    "inference_pb2",
    "openshell_pb2",
    "options_pb2",
    "sandbox_pb2",
]
