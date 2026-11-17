# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Connects straight to an unroutable address, bypassing any proxy, and
# prints the outcome and how long it took.
import json, socket, time

start = time.monotonic()
result = "unknown"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(("198.51.100.1", 80))
    result = "connected"
    s.close()
except ConnectionRefusedError:
    result = "refused"
except PermissionError:
    result = "denied"
except socket.timeout:
    result = "timeout"
except OSError as e:
    result = f"error:{e}"

elapsed_ms = int((time.monotonic() - start) * 1000)
print(json.dumps({"bypass_result": result, "elapsed_ms": elapsed_ms}), flush=True)
