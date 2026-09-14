// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/inferencev1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInferenceRouteConfigToProto(t *testing.T) {
	cfg := &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "my-route",
		NoVerify:     true,
		TimeoutSecs:  120,
	}

	req := InferenceRouteConfigToProto("team-alpha", cfg)

	assert.Equal(t, "openai", req.GetProviderName())
	assert.Equal(t, "gpt-4", req.GetModelId())
	assert.Equal(t, "my-route", req.GetRouteName())
	assert.True(t, req.GetNoVerify())
	assert.False(t, req.GetVerify())
	assert.Equal(t, uint64(120), req.GetTimeoutSecs())
	assert.Equal(t, "team-alpha", req.GetWorkspace())
}

func TestInferenceRouteConfigToProto_NilConfig(t *testing.T) {
	req := InferenceRouteConfigToProto("ws", nil)

	assert.Equal(t, "ws", req.GetWorkspace())
	assert.Empty(t, req.GetProviderName())
}

func TestInferenceRouteConfigToProto_EmptyRouteName(t *testing.T) {
	cfg := &types.InferenceRouteConfig{
		ProviderName: "openai",
		ModelID:      "gpt-4",
		RouteName:    "",
	}

	req := InferenceRouteConfigToProto("ws", cfg)

	assert.Empty(t, req.GetRouteName())
}

func TestInferenceRouteFromSetResponse(t *testing.T) {
	resp := &pb.SetInferenceRouteResponse{
		ProviderName:        "openai",
		ModelId:             "gpt-4",
		Version:             5,
		RouteName:           "my-route",
		ValidationPerformed: true,
		ValidatedEndpoints: []*pb.ValidatedEndpoint{
			{Url: "https://api.openai.com/v1", Protocol: "openai"},
			{Url: "https://backup.openai.com/v1", Protocol: "openai"},
		},
		TimeoutSecs: 120,
		Workspace:   "team-alpha",
	}

	route := InferenceRouteFromSetResponse(resp)

	require.NotNil(t, route)
	assert.Equal(t, "openai", route.ProviderName)
	assert.Equal(t, "gpt-4", route.ModelID)
	assert.Equal(t, uint64(5), route.Version)
	assert.Equal(t, "my-route", route.RouteName)
	assert.True(t, route.ValidationPerformed)
	require.Len(t, route.ValidatedEndpoints, 2)
	assert.Equal(t, "https://api.openai.com/v1", route.ValidatedEndpoints[0].URL)
	assert.Equal(t, "openai", route.ValidatedEndpoints[0].Protocol)
	assert.Equal(t, "https://backup.openai.com/v1", route.ValidatedEndpoints[1].URL)
	assert.Equal(t, uint64(120), route.TimeoutSecs)
	assert.Equal(t, "team-alpha", route.Workspace)
}

func TestInferenceRouteFromSetResponse_Nil(t *testing.T) {
	route := InferenceRouteFromSetResponse(nil)
	assert.Nil(t, route)
}

func TestInferenceRouteFromSetResponse_NoEndpoints(t *testing.T) {
	resp := &pb.SetInferenceRouteResponse{
		ProviderName:        "openai",
		ModelId:             "gpt-4",
		Version:             1,
		ValidationPerformed: false,
	}

	route := InferenceRouteFromSetResponse(resp)

	require.NotNil(t, route)
	assert.Nil(t, route.ValidatedEndpoints)
	assert.False(t, route.ValidationPerformed)
}

func TestInferenceRouteFromGetResponse(t *testing.T) {
	resp := &pb.GetInferenceRouteResponse{
		ProviderName: "vertex",
		ModelId:      "gemini-pro",
		Version:      3,
		RouteName:    "default",
		TimeoutSecs:  60,
		Workspace:    "prod",
	}

	route := InferenceRouteFromGetResponse(resp)

	require.NotNil(t, route)
	assert.Equal(t, "vertex", route.ProviderName)
	assert.Equal(t, "gemini-pro", route.ModelID)
	assert.Equal(t, uint64(3), route.Version)
	assert.Equal(t, "default", route.RouteName)
	assert.Equal(t, uint64(60), route.TimeoutSecs)
	assert.Equal(t, "prod", route.Workspace)
	assert.False(t, route.ValidationPerformed)
	assert.Nil(t, route.ValidatedEndpoints)
}

func TestInferenceRouteFromGetResponse_Nil(t *testing.T) {
	route := InferenceRouteFromGetResponse(nil)
	assert.Nil(t, route)
}

func TestInferenceRouteFromSetResponse_DeepCopy(t *testing.T) {
	protoEndpoints := []*pb.ValidatedEndpoint{
		{Url: "https://original.com", Protocol: "openai"},
	}
	resp := &pb.SetInferenceRouteResponse{
		ProviderName:       "openai",
		ModelId:            "gpt-4",
		Version:            1,
		ValidatedEndpoints: protoEndpoints,
	}

	route := InferenceRouteFromSetResponse(resp)

	// Mutate the proto source; SDK value should be unaffected.
	protoEndpoints[0].Url = "https://mutated.com"
	assert.Equal(t, "https://original.com", route.ValidatedEndpoints[0].URL)
}

func TestInferenceRoundTrip(t *testing.T) {
	cfg := &types.InferenceRouteConfig{
		ProviderName: "anthropic",
		ModelID:      "claude-4",
		RouteName:    "inference-route",
		NoVerify:     false,
		TimeoutSecs:  90,
	}

	req := InferenceRouteConfigToProto("my-ws", cfg)

	assert.Equal(t, cfg.ProviderName, req.GetProviderName())
	assert.Equal(t, cfg.ModelID, req.GetModelId())
	assert.Equal(t, cfg.RouteName, req.GetRouteName())
	assert.Equal(t, cfg.NoVerify, req.GetNoVerify())
	assert.Equal(t, cfg.TimeoutSecs, req.GetTimeoutSecs())
	assert.Equal(t, "my-ws", req.GetWorkspace())
}
