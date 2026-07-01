// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField function inventory, discovery, and allocation.

pub use bf_core::{FunctionKind, FunctionSlot, NetFunction};

pub mod inventory;
pub mod pool;

pub use inventory::{
    FunctionInventory, InventoryError, InventoryResult, StaticFunctionInventory,
    SysfsRepresentorInventory, SysfsVfInventory,
};
pub use pool::FunctionPool;
