// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const url = "http://1.1.1.1/";
console.log(`Attempting GET ${url} through the supervisor`);
const result = httpGet(url);
if (result !== -1) {
  throw new Error(`Expected a supervisor policy denial, received ${result}`);
}
console.log("Request denied by supervisor network policy (expected)");
