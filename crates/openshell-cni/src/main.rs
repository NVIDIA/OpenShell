// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    if let Err(error) = openshell_cni::run() {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}
