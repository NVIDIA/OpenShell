// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/options"
)

func TestTunnelOption_NilIgnored(t *testing.T) {
	cfg := tunnelConfig{closeTimeout: defaultCloseTimeout}
	options.Apply(&cfg, []TunnelOption{
		WithTunnelLogger(nil),
		nil,
		WithCloseTimeout(10 * time.Second),
	})
	assert.Equal(t, 10*time.Second, cfg.closeTimeout)
}
