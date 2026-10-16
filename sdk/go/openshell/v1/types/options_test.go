// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Callers migrating from the positional labels parameter passed nil for an
// unlabeled sandbox. That nil still satisfies CreateOption, so it reaches
// ApplyCreateOptions and must not be invoked.
func TestApplyCreateOptions_IgnoresNilOption(t *testing.T) {
	cfg := ApplyCreateOptions([]CreateOption{nil})

	assert.Nil(t, cfg.Labels())
	assert.Nil(t, cfg.Annotations())
}

func TestApplyCreateOptions_IgnoresNilAmongRealOptions(t *testing.T) {
	cfg := ApplyCreateOptions([]CreateOption{
		nil,
		WithLabels(map[string]string{"env": "dev"}),
		nil,
		WithAnnotations(map[string]string{"source": "cli"}),
		nil,
	})

	assert.Equal(t, map[string]string{"env": "dev"}, cfg.Labels())
	assert.Equal(t, map[string]string{"source": "cli"}, cfg.Annotations())
}

func TestApplyCreateOptions_NoOptions(t *testing.T) {
	cfg := ApplyCreateOptions(nil)

	assert.Nil(t, cfg.Labels())
	assert.Nil(t, cfg.Annotations())
}
