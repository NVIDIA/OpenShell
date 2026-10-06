// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package options provides a shared mechanism for applying functional options
// across all SDK entry points. It enforces a single nil-option rule: nil
// entries in an option list are silently ignored.
package options

// Apply folds opts into target in order, skipping nil entries.
// O is constrained to any named function type whose underlying type is
// func(*T), so callers write options.Apply(&cfg, opts) and both type
// parameters are inferred.
func Apply[T any, O ~func(*T)](target *T, opts []O) {
	for _, opt := range opts {
		if opt != nil {
			opt(target)
		}
	}
}
