// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_EmptyAddress(t *testing.T) {
	_, err := NewClient(Config{Address: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestNewClient_ValidConfig(t *testing.T) {
	client, err := NewClient(Config{
		Address: "localhost:50051",
		Auth:    NoAuth(),
		TLS:     &TLSConfig{Insecure: true},
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	assert.NotNil(t, client.Sandboxes())
	assert.NotNil(t, client.Providers())
	assert.NotNil(t, client.Exec())
	assert.NotNil(t, client.Files())
	assert.NotNil(t, client.Health())

	err = client.Close()
	assert.NoError(t, err)
}

func TestClient_CloseIdempotent(t *testing.T) {
	client, err := NewClient(Config{
		Address: "localhost:50051",
		Auth:    NoAuth(),
		TLS:     &TLSConfig{Insecure: true},
	})
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestNewClient_DefaultAuth(t *testing.T) {
	client, err := NewClient(Config{
		Address: "localhost:50051",
		TLS:     &TLSConfig{Insecure: true},
	})
	require.NoError(t, err)
	require.NotNil(t, client)
	_ = client.Close()
}
