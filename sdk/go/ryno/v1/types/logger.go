// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// Logger defines structured logging for the SDK. Compatible with logr.Logger
// and slog.Logger adapters.
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Error(err error, msg string, keysAndValues ...any)
}
