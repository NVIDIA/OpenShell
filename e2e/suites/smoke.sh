#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

exec cargo test \
	--manifest-path e2e/rust/Cargo.toml \
	--features e2e \
	--test smoke \
	-- --nocapture
