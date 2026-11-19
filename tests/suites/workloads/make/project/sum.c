// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "sum.h"

long sum_to(long n) {
    long total = 0;
    for (long i = 1; i <= n; i++) {
        total += i;
    }
    return total;
}
