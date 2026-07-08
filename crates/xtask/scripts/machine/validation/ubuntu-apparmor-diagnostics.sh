#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

echo "=== recent AppArmor denials ==="
sudo dmesg \
	| grep -E 'apparmor=.*DENIED|profile="unprivileged_userns"' \
	| tail -100 \
	|| true
