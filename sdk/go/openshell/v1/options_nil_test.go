// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/options"
)

func TestRefreshOption_NilIgnored(t *testing.T) {
	cfg := defaultRefreshConfig()
	options.Apply(&cfg, []RefreshOption{
		WithLeeway(5 * time.Second),
		nil,
		WithLeeway(20 * time.Second),
	})
	assert.Equal(t, 20*time.Second, cfg.leeway)
}

func TestForwardOption_NilIgnored(t *testing.T) {
	var cfg forwardConfig
	options.Apply(&cfg, []ForwardOption{
		WithForwardServiceID("svc-a"),
		nil,
		WithForwardServiceID("svc-b"),
	})
	assert.Equal(t, "svc-b", cfg.serviceID)
}

func TestListenOption_NilIgnored(t *testing.T) {
	cfg := listenConfig{bindAddress: "127.0.0.1"}
	options.Apply(&cfg, []ListenOption{
		WithBindAddress("0.0.0.0"),
		nil,
		WithListenServiceID("svc-listen"),
	})
	assert.Equal(t, "0.0.0.0", cfg.bindAddress)
	assert.Equal(t, "svc-listen", cfg.serviceID)
}

func TestTunnelOption_NilIgnored(t *testing.T) {
	var cfg tunnelConfig
	options.Apply(&cfg, []TunnelOption{
		WithTunnelServiceID("svc-x"),
		nil,
		WithTunnelServiceID("svc-y"),
	})
	assert.Equal(t, "svc-y", cfg.serviceID)
}
