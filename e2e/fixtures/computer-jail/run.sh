#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
exec /usr/local/bin/python /fixture/probe.py > /tmp/computer-jail-result.log 2>&1
