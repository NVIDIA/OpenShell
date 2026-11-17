# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Connects to addresses the policy names but the sandbox must still refuse,
# and prints each connect's errno as JSON, 0 for a connection.
import json
import socket

targets = {
    "metadata": ("169.254.169.254", 80),
    "control_plane": ("203.0.113.10", 6443),
    "outside_allowed_ips": ("203.0.113.10", 8080),
}
result = {}
for name, target in targets.items():
    try:
        with socket.create_connection(target, timeout=10):
            result[name] = 0
    except OSError as error:
        result[name] = error.errno
print(json.dumps(result, sort_keys=True))
