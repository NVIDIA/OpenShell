// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// Config holds all settings needed to create a Client.
type Config struct {
	Address string
	TLS     *TLSConfig
	Auth    AuthProvider
}
