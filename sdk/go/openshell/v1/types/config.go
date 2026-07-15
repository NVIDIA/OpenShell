// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// Config holds all settings needed to create a Client.
type Config struct {
	Address string
	TLS     *TLSConfig
	Auth    AuthProvider
	// Timeout is reserved for future use. It is not yet applied.
	Timeout time.Duration
	// RetryPolicy is reserved for future use. It is not yet applied.
	RetryPolicy *RetryPolicy
	// Logger is reserved for future use. It is not yet applied.
	Logger Logger
}
