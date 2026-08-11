// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSandboxFromProto(t *testing.T) {
	gpuCount := uint32(2)
	proto := &pb.Sandbox{
		Metadata: &dm.ObjectMeta{
			Id:                  "sb-1",
			Name:                "my-sandbox",
			CreatedAtMs:         1700000000000,
			Labels:              map[string]string{"env": "dev"},
			Annotations:         map[string]string{"owner": "team-a"},
			ResourceVersion:     3,
			Workspace:           "prod",
			DeletionTimestampMs: 1700000060000,
		},
		CreatedFromTemplate: &pb.SandboxTemplateProvenance{
			Name:            "python",
			ResourceVersion: "7",
		},
		Spec: &pb.SandboxSpec{
			Workload: &pb.SandboxWorkloadConfig{
				Image:       "python:3.12",
				Environment: map[string]string{"FOO": "bar"},
				Resources: &pb.SandboxResources{
					Cpu:      "2",
					Memory:   "4Gi",
					GpuCount: &gpuCount,
				},
			},
			DriverConfig: structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{"kubernetes": structpb.NewBoolValue(true)},
			}).GetStructValue(),
			Providers: []string{"claude", "github"},
		},
		Status: &pb.SandboxStatus{
			SandboxName:          "sb-compute-1",
			AgentPod:             "agent-pod-xyz",
			AgentFd:              "fd-agent",
			SandboxFd:            "fd-sandbox",
			Phase:                pb.SandboxPhase_SANDBOX_PHASE_READY,
			CurrentPolicyVersion: 7,
			Conditions: []*pb.SandboxCondition{
				{
					Type:               "Ready",
					Status:             "True",
					Reason:             "AllGood",
					Message:            "Sandbox is ready",
					LastTransitionTime: "2024-01-01T00:00:00Z",
				},
			},
		},
	}

	s := SandboxFromProto(proto)

	require.NotNil(t, s)
	assert.Equal(t, "sb-1", s.ID)
	assert.Equal(t, "my-sandbox", s.Name)
	assert.Equal(t, time.UnixMilli(1700000000000).UTC(), s.CreatedAt)
	assert.Equal(t, map[string]string{"env": "dev"}, s.Labels)
	assert.Equal(t, map[string]string{"owner": "team-a"}, s.Annotations)
	assert.Equal(t, uint64(3), s.ResourceVersion)
	assert.Equal(t, "prod", s.Workspace)
	require.NotNil(t, s.DeletionTimestamp)
	assert.Equal(t, time.UnixMilli(1700000060000).UTC(), *s.DeletionTimestamp)
	require.NotNil(t, s.CreatedFromTemplate)
	assert.Equal(t, "python", s.CreatedFromTemplate.Name)
	assert.Equal(t, "7", s.CreatedFromTemplate.ResourceVersion)

	require.NotNil(t, s.Spec.Workload)
	assert.Equal(t, "python:3.12", s.Spec.Workload.Image)
	assert.Equal(t, map[string]string{"FOO": "bar"}, s.Spec.Workload.Environment)
	require.NotNil(t, s.Spec.Workload.Resources)
	assert.Equal(t, "2", s.Spec.Workload.Resources.CPU)
	assert.Equal(t, "4Gi", s.Spec.Workload.Resources.Memory)
	require.NotNil(t, s.Spec.Workload.Resources.GPUCount)
	assert.Equal(t, uint32(2), *s.Spec.Workload.Resources.GPUCount)
	assert.Equal(t, map[string]any{"kubernetes": true}, s.Spec.DriverConfig)
	assert.Equal(t, []string{"claude", "github"}, s.Spec.Providers)

	assert.Equal(t, "sb-compute-1", s.Status.SandboxName)
	assert.Equal(t, "agent-pod-xyz", s.Status.AgentPod)
	assert.Equal(t, "fd-agent", s.Status.AgentFd)
	assert.Equal(t, "fd-sandbox", s.Status.SandboxFd)
	assert.Equal(t, v1.SandboxReady, s.Status.Phase)
	assert.Equal(t, uint32(7), s.Status.CurrentPolicyVersion)
	require.Len(t, s.Status.Conditions, 1)
	assert.Equal(t, "Ready", s.Status.Conditions[0].Type)
	assert.Equal(t, "True", s.Status.Conditions[0].Status)
	assert.Equal(t, "AllGood", s.Status.Conditions[0].Reason)
	assert.Equal(t, "Sandbox is ready", s.Status.Conditions[0].Message)
	assert.Equal(t, "2024-01-01T00:00:00Z", s.Status.Conditions[0].LastTransitionTime)
}

func TestSandboxFromProto_NilFields(t *testing.T) {
	s := SandboxFromProto(&pb.Sandbox{})

	require.NotNil(t, s)
	assert.Empty(t, s.ID)
	assert.Empty(t, s.Name)
	assert.True(t, s.CreatedAt.IsZero())
	assert.Nil(t, s.Spec.Workload)
	assert.Equal(t, v1.SandboxUnknown, s.Status.Phase)
}

func TestSandboxFromProto_Nil(t *testing.T) {
	assert.Nil(t, SandboxFromProto(nil))
}

func TestSandboxPhaseFromProto(t *testing.T) {
	tests := []struct {
		proto    pb.SandboxPhase
		expected v1.SandboxPhase
	}{
		{pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING, v1.SandboxProvisioning},
		{pb.SandboxPhase_SANDBOX_PHASE_READY, v1.SandboxReady},
		{pb.SandboxPhase_SANDBOX_PHASE_ERROR, v1.SandboxError},
		{pb.SandboxPhase_SANDBOX_PHASE_DELETING, v1.SandboxDeleting},
		{pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN, v1.SandboxUnknown},
		{pb.SandboxPhase_SANDBOX_PHASE_UNSPECIFIED, v1.SandboxUnknown},
		{pb.SandboxPhase(999), v1.SandboxUnknown},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, SandboxPhaseFromProto(tt.proto), "phase %v", tt.proto)
	}
}

func TestSandboxPhaseToProto(t *testing.T) {
	tests := []struct {
		sdk      v1.SandboxPhase
		expected pb.SandboxPhase
	}{
		{v1.SandboxProvisioning, pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		{v1.SandboxReady, pb.SandboxPhase_SANDBOX_PHASE_READY},
		{v1.SandboxError, pb.SandboxPhase_SANDBOX_PHASE_ERROR},
		{v1.SandboxDeleting, pb.SandboxPhase_SANDBOX_PHASE_DELETING},
		{v1.SandboxUnknown, pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN},
		{v1.SandboxPhase("bogus"), pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, SandboxPhaseToProto(tt.sdk), "phase %v", tt.sdk)
	}
}

func TestSandboxToProto(t *testing.T) {
	gpuCount := uint32(4)
	delTime := time.UnixMilli(1700000060000).UTC()
	s := &v1.Sandbox{
		ID:                "sb-1",
		Name:              "my-sandbox",
		CreatedAt:         time.UnixMilli(1700000000000).UTC(),
		Labels:            map[string]string{"env": "dev"},
		Annotations:       map[string]string{"owner": "team-a"},
		ResourceVersion:   3,
		Workspace:         "prod",
		DeletionTimestamp: &delTime,
		CreatedFromTemplate: &v1.SandboxTemplateProvenance{
			Name:            "python",
			ResourceVersion: "9",
		},
		Spec: v1.SandboxSpec{
			Workload: &v1.SandboxWorkloadConfig{
				Image:       "img:v1",
				Environment: map[string]string{"E": "V"},
				Resources: &v1.SandboxResources{
					CPU:      "500m",
					Memory:   "1Gi",
					GPUCount: &gpuCount,
				},
			},
			DriverConfig: map[string]any{"kubernetes": map[string]any{"runtime_class_name": "kata"}},
			Providers:    []string{"prov-a"},
		},
	}

	p, err := SandboxToProto(s)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, p.Metadata)
	assert.Equal(t, "sb-1", p.Metadata.Id)
	assert.Equal(t, "my-sandbox", p.Metadata.Name)
	assert.Equal(t, int64(1700000000000), p.Metadata.CreatedAtMs)
	assert.Equal(t, map[string]string{"env": "dev"}, p.Metadata.Labels)
	assert.Equal(t, map[string]string{"owner": "team-a"}, p.Metadata.Annotations)
	assert.Equal(t, uint64(3), p.Metadata.ResourceVersion)
	assert.Equal(t, "prod", p.Metadata.Workspace)
	assert.Equal(t, int64(1700000060000), p.Metadata.DeletionTimestampMs)
	require.NotNil(t, p.CreatedFromTemplate)
	assert.Equal(t, "python", p.CreatedFromTemplate.Name)
	assert.Equal(t, "9", p.CreatedFromTemplate.ResourceVersion)

	require.NotNil(t, p.Spec)
	require.NotNil(t, p.Spec.Workload)
	assert.Equal(t, "img:v1", p.Spec.Workload.Image)
	assert.Equal(t, map[string]string{"E": "V"}, p.Spec.Workload.Environment)
	require.NotNil(t, p.Spec.Workload.Resources)
	assert.Equal(t, "500m", p.Spec.Workload.Resources.Cpu)
	assert.Equal(t, "1Gi", p.Spec.Workload.Resources.Memory)
	assert.Equal(t, uint32(4), p.Spec.Workload.Resources.GetGpuCount())
	assert.Equal(t, []string{"prov-a"}, p.Spec.Providers)
	require.NotNil(t, p.Spec.DriverConfig)
	assert.Equal(t, "kata", p.Spec.DriverConfig.Fields["kubernetes"].GetStructValue().Fields["runtime_class_name"].GetStringValue())
}

func TestSandboxToProto_Nil(t *testing.T) {
	p, err := SandboxToProto(nil)
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestSandboxToProto_NilWorkload(t *testing.T) {
	p, err := SandboxToProto(&v1.Sandbox{})
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, p.Spec)
	assert.Nil(t, p.Spec.Workload)
}

func TestSandboxRoundTrip(t *testing.T) {
	gpuCount := uint32(1)
	rtDelTime := time.UnixMilli(1700000090000).UTC()
	original := &v1.Sandbox{
		ID:                "sb-rt",
		Name:              "round-trip",
		CreatedAt:         time.UnixMilli(1700000000000).UTC(),
		Labels:            map[string]string{"team": "platform"},
		Annotations:       map[string]string{"note": "rt-test"},
		ResourceVersion:   10,
		Workspace:         "staging",
		DeletionTimestamp: &rtDelTime,
		Spec: v1.SandboxSpec{
			Workload: &v1.SandboxWorkloadConfig{
				Image: "img:rt",
				Resources: &v1.SandboxResources{
					GPUCount: &gpuCount,
				},
			},
			Providers: []string{"p1", "p2"},
			Policy: &v1.SandboxPolicy{
				Version: 3,
				Filesystem: &v1.FilesystemPolicy{
					IncludeWorkdir: true,
					ReadOnly:       []string{"/etc", "/usr/share"},
					ReadWrite:      []string{"/tmp"},
				},
				Landlock: &v1.LandlockPolicy{
					Compatibility: "best_effort",
				},
				Process: &v1.ProcessPolicy{
					RunAsUser:  "sandbox",
					RunAsGroup: "sandbox-group",
				},
				NetworkPolicies: map[string]v1.NetworkPolicyRule{
					"web": {
						Name: "web",
						Endpoints: []v1.PolicyNetworkEndpoint{
							{Host: "api.example.com", Port: 443, Protocol: "rest"},
						},
					},
				},
			},
		},
	}

	p, err := SandboxToProto(original)
	require.NoError(t, err)
	back := SandboxFromProto(p)

	assert.Equal(t, original.ID, back.ID)
	assert.Equal(t, original.Name, back.Name)
	assert.Equal(t, original.CreatedAt, back.CreatedAt)
	assert.Equal(t, original.Labels, back.Labels)
	assert.Equal(t, original.Annotations, back.Annotations)
	assert.Equal(t, original.ResourceVersion, back.ResourceVersion)
	assert.Equal(t, original.Workspace, back.Workspace)
	require.NotNil(t, back.DeletionTimestamp)
	assert.Equal(t, *original.DeletionTimestamp, *back.DeletionTimestamp)
	require.NotNil(t, back.Spec.Workload)
	assert.Equal(t, original.Spec.Workload.Image, back.Spec.Workload.Image)
	require.NotNil(t, back.Spec.Workload.Resources)
	require.NotNil(t, back.Spec.Workload.Resources.GPUCount)
	assert.Equal(t, *original.Spec.Workload.Resources.GPUCount, *back.Spec.Workload.Resources.GPUCount)
	assert.Equal(t, original.Spec.Providers, back.Spec.Providers)

	require.NotNil(t, back.Spec.Policy)
	assert.Equal(t, uint32(3), back.Spec.Policy.Version)
	require.NotNil(t, back.Spec.Policy.Filesystem)
	assert.True(t, back.Spec.Policy.Filesystem.IncludeWorkdir)
	assert.Equal(t, []string{"/etc", "/usr/share"}, back.Spec.Policy.Filesystem.ReadOnly)
	assert.Equal(t, []string{"/tmp"}, back.Spec.Policy.Filesystem.ReadWrite)
	require.NotNil(t, back.Spec.Policy.Landlock)
	assert.Equal(t, "best_effort", back.Spec.Policy.Landlock.Compatibility)
	require.NotNil(t, back.Spec.Policy.Process)
	assert.Equal(t, "sandbox", back.Spec.Policy.Process.RunAsUser)
	assert.Equal(t, "sandbox-group", back.Spec.Policy.Process.RunAsGroup)
	require.Len(t, back.Spec.Policy.NetworkPolicies, 1)
	webRule, ok := back.Spec.Policy.NetworkPolicies["web"]
	require.True(t, ok)
	assert.Equal(t, "web", webRule.Name)
	require.Len(t, webRule.Endpoints, 1)
	assert.Equal(t, "api.example.com", webRule.Endpoints[0].Host)
}

func TestSandboxSpecToProto(t *testing.T) {
	gpuCount := uint32(3)
	spec := &v1.SandboxSpec{
		Workload: &v1.SandboxWorkloadConfig{
			Image:       "img:spec",
			Environment: map[string]string{"X": "Y"},
			Resources: &v1.SandboxResources{
				CPU:      "2",
				Memory:   "8Gi",
				GPUCount: &gpuCount,
			},
		},
		Providers: []string{"prov"},
		Policy: &v1.SandboxPolicy{
			Version: 2,
			Filesystem: &v1.FilesystemPolicy{
				ReadOnly: []string{"/etc"},
			},
		},
	}

	p, err := SandboxSpecToProto(spec)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotNil(t, p.Workload)
	assert.Equal(t, "img:spec", p.Workload.Image)
	assert.Equal(t, map[string]string{"X": "Y"}, p.Workload.Environment)
	require.NotNil(t, p.Workload.Resources)
	assert.Equal(t, "2", p.Workload.Resources.Cpu)
	assert.Equal(t, "8Gi", p.Workload.Resources.Memory)
	assert.Equal(t, uint32(3), p.Workload.Resources.GetGpuCount())
	assert.Equal(t, []string{"prov"}, p.Providers)

	require.NotNil(t, p.Policy)
	assert.Equal(t, uint32(2), p.Policy.Version)
	require.NotNil(t, p.Policy.Filesystem)
	assert.Equal(t, []string{"/etc"}, p.Policy.Filesystem.ReadOnly)
}

func TestSandboxSpecToProto_Nil(t *testing.T) {
	p, err := SandboxSpecToProto(nil)
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestSandboxSpecToProto_InvalidMapReturnsError(t *testing.T) {
	spec := &v1.SandboxSpec{
		DriverConfig: map[string]any{"bad": make(chan int)},
	}

	p, err := SandboxSpecToProto(spec)
	require.Error(t, err, "SandboxSpecToProto must return an error for unconvertible map values")
	assert.Nil(t, p)
	assert.Contains(t, err.Error(), "convert driver config")
}

func TestSandboxTemplateRoundTrip(t *testing.T) {
	readyWithin := 15 * time.Second
	template := &v1.SandboxTemplate{
		ID:              "tmpl-1",
		Name:            "python",
		CreatedAt:       time.UnixMilli(1700000000000).UTC(),
		Labels:          map[string]string{"runtime": "python"},
		ResourceVersion: 5,
		Workspace:       "default",
		Spec: v1.SandboxTemplateSpec{
			Workload: &v1.SandboxWorkloadConfig{Image: "python:3.12"},
			DriverConfig: map[string]any{
				"kubernetes": map[string]any{"runtime_class_name": "kata"},
			},
			DesiredServiceLevel: &v1.SandboxServiceLevel{
				Startup: &v1.SandboxStartup{
					ReadyWithin: readyWithin,
					MaxBurst:    2,
				},
			},
		},
	}

	p, err := SandboxTemplateToProto(template)
	require.NoError(t, err)
	back := SandboxTemplateFromProto(p)

	require.NotNil(t, back)
	assert.Equal(t, template.ID, back.ID)
	assert.Equal(t, template.Name, back.Name)
	assert.Equal(t, template.CreatedAt, back.CreatedAt)
	assert.Equal(t, template.Labels, back.Labels)
	assert.Equal(t, template.ResourceVersion, back.ResourceVersion)
	assert.Equal(t, template.Workspace, back.Workspace)
	require.NotNil(t, back.Spec.Workload)
	assert.Equal(t, "python:3.12", back.Spec.Workload.Image)
	assert.Equal(t, map[string]any{"kubernetes": map[string]any{"runtime_class_name": "kata"}}, back.Spec.DriverConfig)
	require.NotNil(t, back.Spec.DesiredServiceLevel)
	require.NotNil(t, back.Spec.DesiredServiceLevel.Startup)
	assert.Equal(t, readyWithin, back.Spec.DesiredServiceLevel.Startup.ReadyWithin)
	assert.Equal(t, uint32(2), back.Spec.DesiredServiceLevel.Startup.MaxBurst)
}

func TestSandboxTemplateFromProto_Duration(t *testing.T) {
	template := SandboxTemplateFromProto(&pb.SandboxTemplate{
		Spec: &pb.SandboxTemplateSpec{
			DesiredServiceLevel: &pb.SandboxServiceLevel{
				Startup: &pb.SandboxStartup{
					ReadyWithin: durationpb.New(30 * time.Second),
					MaxBurst:    4,
				},
			},
		},
	})

	require.NotNil(t, template)
	require.NotNil(t, template.Spec.DesiredServiceLevel)
	require.NotNil(t, template.Spec.DesiredServiceLevel.Startup)
	assert.Equal(t, 30*time.Second, template.Spec.DesiredServiceLevel.Startup.ReadyWithin)
	assert.Equal(t, uint32(4), template.Spec.DesiredServiceLevel.Startup.MaxBurst)
}
