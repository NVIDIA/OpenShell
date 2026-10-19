// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

console.log("Hello from js-sbx");
try {
  fetch("https://example.com");
  throw new Error("Expected network access to be disabled");
} catch (error) {
  if (error.message !== "Network access is disabled") throw error;
  console.log(error.message);
}
