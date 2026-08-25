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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSandboxFromProto(t *testing.T) {
	userNS := true
	gpuCount := uint32(2)
	exitCode := int32(0)
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
		Spec: &pb.SandboxSpec{
			LogLevel:    "debug",
			Environment: map[string]string{"FOO": "bar"},
			Template: &pb.SandboxTemplate{
				Image:            "nvidia/sandbox:latest",
				RuntimeClassName: "kata",
				AgentSocket:      "/var/run/agent.sock",
				Labels:           map[string]string{"app": "test"},
				Annotations:      map[string]string{"note": "hello"},
				Environment:      map[string]string{"TMPL_VAR": "val"},
				UserNamespaces:   &userNS,
				Resources: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{"cpu": "2", "memory": "4Gi"})
					return s
				}(),
				DriverConfig: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{"runtime": "kata", "nested": map[string]any{"key": "val"}})
					return s
				}(),
			},
			Providers: []string{"claude", "github"},
			ResourceRequirements: &pb.ResourceRequirements{
				Gpu: &pb.GpuResourceRequirements{
					Count: &gpuCount,
				},
			},
			Command: []string{"/opt/agent", "--serve"},
			Tty:     false,
		},
		Status: &pb.SandboxStatus{
			SandboxName:           "sb-compute-1",
			AgentPod:              "agent-pod-xyz",
			AgentFd:               "fd-agent",
			SandboxFd:             "fd-sandbox",
			Phase:                 pb.SandboxPhase_SANDBOX_PHASE_READY,
			CurrentPolicyVersion:  7,
			MainProcessInstanceId: "instance-1",
			ExitCode:              &exitCode,
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

	// Spec
	assert.Equal(t, "debug", s.Spec.LogLevel)
	assert.Equal(t, map[string]string{"FOO": "bar"}, s.Spec.Environment)
	assert.Equal(t, []string{"claude", "github"}, s.Spec.Providers)
	require.NotNil(t, s.Spec.GPUCount)
	assert.Equal(t, uint32(2), *s.Spec.GPUCount)
	assert.Equal(t, []string{"/opt/agent", "--serve"}, s.Spec.Command)
	assert.False(t, s.Spec.TTY)

	// Template
	require.NotNil(t, s.Spec.Template)
	assert.Equal(t, "nvidia/sandbox:latest", s.Spec.Template.Image)
	assert.Equal(t, "kata", s.Spec.Template.RuntimeClassName)
	assert.Equal(t, "/var/run/agent.sock", s.Spec.Template.AgentSocket)
	assert.Equal(t, map[string]string{"app": "test"}, s.Spec.Template.Labels)
	assert.Equal(t, map[string]string{"note": "hello"}, s.Spec.Template.Annotations)
	assert.Equal(t, map[string]string{"TMPL_VAR": "val"}, s.Spec.Template.Environment)
	require.NotNil(t, s.Spec.Template.UserNamespaces)
	assert.True(t, *s.Spec.Template.UserNamespaces)
	assert.Equal(t, map[string]any{"cpu": "2", "memory": "4Gi"}, s.Spec.Template.Resources)
	assert.Equal(t, "kata", s.Spec.Template.DriverConfig["runtime"])
	nested, ok := s.Spec.Template.DriverConfig["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "val", nested["key"])

	// Status
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
	require.NotNil(t, s.Status.ExitCode)
	assert.Equal(t, int32(0), *s.Status.ExitCode)
}

func TestSandboxFromProto_TemplateResourcesDeepCopy(t *testing.T) {
	proto := &pb.Sandbox{
		Spec: &pb.SandboxSpec{
			Template: &pb.SandboxTemplate{
				Image: "img:v1",
				Resources: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{"cpu": "2"})
					return s
				}(),
				DriverConfig: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{"runtime": "kata"})
					return s
				}(),
			},
		},
	}

	s := SandboxFromProto(proto)
	require.NotNil(t, s)

	proto.Spec.Template.Resources.Fields["cpu"] = structpb.NewStringValue("MUTATED")
	assert.Equal(t, "2", s.Spec.Template.Resources["cpu"], "Resources must be deep copied")

	proto.Spec.Template.DriverConfig.Fields["runtime"] = structpb.NewStringValue("MUTATED")
	assert.Equal(t, "kata", s.Spec.Template.DriverConfig["runtime"], "DriverConfig must be deep copied")
}

func TestSandboxFromProto_NilFields(t *testing.T) {
	proto := &pb.Sandbox{}

	s := SandboxFromProto(proto)

	require.NotNil(t, s)
	assert.Empty(t, s.ID)
	assert.Empty(t, s.Name)
	assert.True(t, s.CreatedAt.IsZero())
	assert.Nil(t, s.Spec.Template)
	assert.Nil(t, s.Spec.GPUCount)
	assert.Equal(t, v1.SandboxUnknown, s.Status.Phase)
}

func TestSandboxFromProto_Nil(t *testing.T) {
	s := SandboxFromProto(nil)
	assert.Nil(t, s)
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
		{pb.SandboxPhase_SANDBOX_PHASE_STOPPING, v1.SandboxStopping},
		{pb.SandboxPhase_SANDBOX_PHASE_STOPPED, v1.SandboxStopped},
		{pb.SandboxPhase_SANDBOX_PHASE_STARTING, v1.SandboxStarting},
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
		{v1.SandboxStopping, pb.SandboxPhase_SANDBOX_PHASE_STOPPING},
		{v1.SandboxStopped, pb.SandboxPhase_SANDBOX_PHASE_STOPPED},
		{v1.SandboxStarting, pb.SandboxPhase_SANDBOX_PHASE_STARTING},
		{v1.SandboxPhase("bogus"), pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, SandboxPhaseToProto(tt.sdk), "phase %v", tt.sdk)
	}
}

func TestSandboxToProto(t *testing.T) {
	userNS := true
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
		Spec: v1.SandboxSpec{
			LogLevel:    "info",
			Environment: map[string]string{"KEY": "val"},
			Template: &v1.SandboxTemplate{
				Image:            "img:v1",
				RuntimeClassName: "runc",
				AgentSocket:      "/sock",
				Labels:           map[string]string{"l": "v"},
				Annotations:      map[string]string{"a": "v"},
				Environment:      map[string]string{"E": "V"},
				UserNamespaces:   &userNS,
			},
			Providers: []string{"prov-a"},
			GPUCount:  &gpuCount,
			Command:   []string{"/opt/agent", "--serve"},
			TTY:       false,
		},
	}

	p := SandboxToProto(s)

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

	require.NotNil(t, p.Spec)
	assert.Equal(t, "info", p.Spec.LogLevel)
	assert.Equal(t, map[string]string{"KEY": "val"}, p.Spec.Environment)
	assert.Equal(t, []string{"prov-a"}, p.Spec.Providers)
	assert.Equal(t, []string{"/opt/agent", "--serve"}, p.Spec.Command)
	assert.False(t, p.Spec.Tty)

	require.NotNil(t, p.Spec.ResourceRequirements)
	require.NotNil(t, p.Spec.ResourceRequirements.Gpu)
	assert.Equal(t, uint32(4), p.Spec.ResourceRequirements.Gpu.GetCount())

	require.NotNil(t, p.Spec.Template)
	assert.Equal(t, "img:v1", p.Spec.Template.Image)
	assert.Equal(t, "runc", p.Spec.Template.RuntimeClassName)
	assert.Equal(t, "/sock", p.Spec.Template.AgentSocket)
	assert.Equal(t, map[string]string{"l": "v"}, p.Spec.Template.Labels)
	assert.Equal(t, map[string]string{"a": "v"}, p.Spec.Template.Annotations)
	assert.Equal(t, map[string]string{"E": "V"}, p.Spec.Template.Environment)
	require.NotNil(t, p.Spec.Template.UserNamespaces)
	assert.True(t, *p.Spec.Template.UserNamespaces)
}

func TestSandboxToProto_Nil(t *testing.T) {
	p := SandboxToProto(nil)
	assert.Nil(t, p)
}

func TestSandboxToProto_NilTemplate(t *testing.T) {
	s := &v1.Sandbox{
		Spec: v1.SandboxSpec{
			LogLevel: "warn",
		},
	}

	p := SandboxToProto(s)

	require.NotNil(t, p)
	require.NotNil(t, p.Spec)
	assert.Nil(t, p.Spec.Template)
	assert.Nil(t, p.Spec.ResourceRequirements)
}

func TestSandboxRoundTrip(t *testing.T) {
	userNS := false
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
			LogLevel:    "trace",
			Environment: map[string]string{"A": "B"},
			Template: &v1.SandboxTemplate{
				Image:          "img:rt",
				UserNamespaces: &userNS,
			},
			Providers: []string{"p1", "p2"},
			GPUCount:  &gpuCount,
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
							{
								Host:     "api.example.com",
								Port:     443,
								Protocol: "rest",
								CredentialBinding: &v1.NetworkCredentialBinding{
									Provider: "api-credentials",
								},
							},
						},
					},
				},
			},
		},
	}

	p := SandboxToProto(original)
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
	assert.Equal(t, original.Spec.LogLevel, back.Spec.LogLevel)
	assert.Equal(t, original.Spec.Environment, back.Spec.Environment)
	assert.Equal(t, original.Spec.Providers, back.Spec.Providers)
	require.NotNil(t, back.Spec.GPUCount)
	assert.Equal(t, *original.Spec.GPUCount, *back.Spec.GPUCount)
	require.NotNil(t, back.Spec.Template)
	assert.Equal(t, original.Spec.Template.Image, back.Spec.Template.Image)
	require.NotNil(t, back.Spec.Template.UserNamespaces)
	assert.Equal(t, *original.Spec.Template.UserNamespaces, *back.Spec.Template.UserNamespaces)

	// Policy round-trip
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
	require.NotNil(t, webRule.Endpoints[0].CredentialBinding)
	assert.Equal(t, "api-credentials", webRule.Endpoints[0].CredentialBinding.Provider)
}

func TestSandboxSpecToProto(t *testing.T) {
	gpuCount := uint32(3)
	spec := &v1.SandboxSpec{
		LogLevel:    "debug",
		Environment: map[string]string{"X": "Y"},
		Template: &v1.SandboxTemplate{
			Image:        "img:spec",
			Resources:    map[string]any{"cpu": "4"},
			DriverConfig: map[string]any{"runtime": "kata"},
		},
		Providers: []string{"prov"},
		GPUCount:  &gpuCount,
		Policy: &v1.SandboxPolicy{
			Version: 2,
			Filesystem: &v1.FilesystemPolicy{
				ReadOnly: []string{"/etc"},
			},
		},
	}

	p := SandboxSpecToProto(spec)

	require.NotNil(t, p)
	assert.Equal(t, "debug", p.LogLevel)
	assert.Equal(t, map[string]string{"X": "Y"}, p.Environment)
	assert.Equal(t, []string{"prov"}, p.Providers)
	require.NotNil(t, p.ResourceRequirements)
	assert.Equal(t, uint32(3), p.ResourceRequirements.Gpu.GetCount())
	require.NotNil(t, p.Template)
	assert.Equal(t, "img:spec", p.Template.Image)
	require.NotNil(t, p.Template.Resources)
	assert.Equal(t, "4", p.Template.Resources.Fields["cpu"].GetStringValue())
	require.NotNil(t, p.Template.DriverConfig)
	assert.Equal(t, "kata", p.Template.DriverConfig.Fields["runtime"].GetStringValue())

	// Policy conversion
	require.NotNil(t, p.Policy)
	assert.Equal(t, uint32(2), p.Policy.Version)
	require.NotNil(t, p.Policy.Filesystem)
	assert.Equal(t, []string{"/etc"}, p.Policy.Filesystem.ReadOnly)
}

func TestSandboxSpecToProto_Nil(t *testing.T) {
	p := SandboxSpecToProto(nil)
	assert.Nil(t, p)
}

// Verify proto import is used (suppress unused import warning).
var _ = proto.Marshal
