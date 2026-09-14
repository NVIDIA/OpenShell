// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceEndpointFromProto(t *testing.T) {
	resp := &pb.ServiceEndpointResponse{
		Endpoint: &pb.ServiceEndpoint{
			Metadata: &dm.ObjectMeta{
				Id: "svc-1",
			},
			SandboxId:   "sb-1",
			SandboxName: "my-sandbox",
			ServiceName: "http-server",
			TargetPort:  8080,
			Domain:      true,
		},
		Url: "https://svc-1.example.com",
	}

	se := ServiceEndpointFromProto(resp)

	require.NotNil(t, se)
	assert.Equal(t, "svc-1", se.ID)
	assert.Equal(t, "sb-1", se.SandboxID)
	assert.Equal(t, "my-sandbox", se.SandboxName)
	assert.Equal(t, "http-server", se.ServiceName)
	assert.Equal(t, uint32(8080), se.TargetPort)
	assert.True(t, se.Domain)
	assert.Equal(t, "https://svc-1.example.com", se.URL)
}

func TestServiceEndpointFromProto_NilEndpoint(t *testing.T) {
	resp := &pb.ServiceEndpointResponse{
		Url: "https://orphan.example.com",
	}

	se := ServiceEndpointFromProto(resp)

	require.NotNil(t, se)
	assert.Empty(t, se.ID)
	assert.Empty(t, se.SandboxID)
	assert.Equal(t, "https://orphan.example.com", se.URL)
}

func TestServiceEndpointFromProto_NilMetadata(t *testing.T) {
	resp := &pb.ServiceEndpointResponse{
		Endpoint: &pb.ServiceEndpoint{
			SandboxId:   "sb-2",
			ServiceName: "api",
			TargetPort:  3000,
		},
	}

	se := ServiceEndpointFromProto(resp)

	require.NotNil(t, se)
	assert.Empty(t, se.ID)
	assert.Equal(t, "sb-2", se.SandboxID)
	assert.Equal(t, "api", se.ServiceName)
	assert.Equal(t, uint32(3000), se.TargetPort)
}

func TestServiceEndpointFromProto_Nil(t *testing.T) {
	se := ServiceEndpointFromProto(nil)
	assert.Nil(t, se)
}

func TestServiceEndpointToProto(t *testing.T) {
	se := &v1.ServiceEndpoint{
		ID:          "svc-1",
		SandboxID:   "sb-1",
		SandboxName: "my-sandbox",
		ServiceName: "http-server",
		TargetPort:  8080,
		Domain:      true,
		URL:         "https://svc-1.example.com",
	}

	resp := ServiceEndpointToProto(se)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Endpoint)
	require.NotNil(t, resp.Endpoint.Metadata)
	assert.Equal(t, "svc-1", resp.Endpoint.Metadata.Id)
	assert.Equal(t, "sb-1", resp.Endpoint.SandboxId)
	assert.Equal(t, "my-sandbox", resp.Endpoint.SandboxName)
	assert.Equal(t, "http-server", resp.Endpoint.ServiceName)
	assert.Equal(t, uint32(8080), resp.Endpoint.TargetPort)
	assert.True(t, resp.Endpoint.Domain)
	assert.Equal(t, "https://svc-1.example.com", resp.Url)
}

func TestServiceEndpointToProto_Nil(t *testing.T) {
	resp := ServiceEndpointToProto(nil)
	assert.Nil(t, resp)
}

func TestServiceEndpointRoundTrip(t *testing.T) {
	original := &v1.ServiceEndpoint{
		ID:          "svc-rt",
		SandboxID:   "sb-rt",
		SandboxName: "round-trip",
		ServiceName: "web",
		TargetPort:  9090,
		Domain:      false,
		URL:         "http://localhost:9090",
	}

	proto := ServiceEndpointToProto(original)
	back := ServiceEndpointFromProto(proto)

	require.NotNil(t, back)
	assert.Equal(t, original.ID, back.ID)
	assert.Equal(t, original.SandboxID, back.SandboxID)
	assert.Equal(t, original.SandboxName, back.SandboxName)
	assert.Equal(t, original.ServiceName, back.ServiceName)
	assert.Equal(t, original.TargetPort, back.TargetPort)
	assert.Equal(t, original.Domain, back.Domain)
	assert.Equal(t, original.URL, back.URL)
}
