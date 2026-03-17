#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mkdir -p deploy/docker/.build/charts

echo "Packaging helm chart..."
helm package deploy/helm/openshell -d deploy/docker/.build/charts/

echo "Building cluster image..."
exec tasks/scripts/docker-build-image.sh cluster "$@"
