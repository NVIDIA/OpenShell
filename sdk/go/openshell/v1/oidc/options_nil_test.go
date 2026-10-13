// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/options"
)

func TestLoginOption_NilIgnored(t *testing.T) {
	var cfg loginConfig
	options.Apply(&cfg, []LoginOption{
		WithIssuer("https://auth.example.com"),
		nil,
		WithClientID("my-app"),
	})
	assert.Equal(t, "https://auth.example.com", cfg.issuer)
	assert.Equal(t, "my-app", cfg.clientID)
}
