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

// Counts once per second of running time. The guest has no timers, so it
// busy-waits. Suspend partway through; after resume the count continues from
// the value held in the isolate's memory.
const started = Date.now();
let count = 0;
let next = Date.now() + 1000;
while (count < 12) {
  if (Date.now() >= next) {
    count += 1;
    next = Date.now() + 1000;
    console.log(`count ${count} (${Math.round((Date.now() - started) / 1000)}s since start)`);
  }
}
console.log("done");
