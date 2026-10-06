// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogOption_NilIgnored(t *testing.T) {
	cfg := ApplyLogOptions([]LogOption{
		WithLogLines(100),
		nil,
		WithLogMinLevel("error"),
	})
	assert.Equal(t, uint32(100), cfg.Lines())
	assert.Equal(t, "error", cfg.MinLevel())
}

func TestGetDraftOption_NilIgnored(t *testing.T) {
	cfg := ApplyGetDraftOptions([]GetDraftOption{
		WithStatusFilter("pending"),
		nil,
		WithStatusFilter("approved"),
	})
	assert.Equal(t, "approved", cfg.StatusFilter())
}
