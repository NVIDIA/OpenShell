// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/options"
)

func TestClientOption_NilIgnored(t *testing.T) {
	var cfg clientConfig
	options.Apply(&cfg, []ClientOption{
		WithTimeout(30 * time.Second),
		nil,
		WithLogger(nil),
	})
	assert.Equal(t, 30*time.Second, cfg.timeout)
}
