// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include "greet.h"
#include "sum.h"

int main(void) {
    greet("sandbox");
    printf("sum(1..100) = %ld\n", sum_to(100));
    return 0;
}
