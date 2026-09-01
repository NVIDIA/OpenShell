// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSandboxTemplateClient() *fakeSandboxTemplateClient {
	store := newobjectStore(sandboxWorkloadTemplateName, copySandboxWorkloadTemplate)
	return newFakeSandboxTemplateClient(store, func() bool { return false })
}

func testSandboxWorkloadTemplate(name string) *types.SandboxWorkloadTemplate {
	return &types.SandboxWorkloadTemplate{
		Name: name,
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "registry.example.com/agent:latest"},
		},
	}
}

func TestIsDNS1123Label(t *testing.T) {
	tests := map[string]bool{
		"":                      false,
		"gpu-kata":              true,
		"Invalid_Template_Name": false,
		"-gpu":                  false,
		"gpu-":                  false,
		"gpu--kata":             false,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": false,
	}

	for name, want := range tests {
		assert.Equal(t, want, isDNS1123Label(name), "name %q", name)
	}
}

func TestSandboxTemplate_CreateGetListDelete(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := &types.SandboxWorkloadTemplate{
		Name:   "gpu-kata",
		Labels: map[string]string{"team": "platform"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload:     &types.SandboxWorkloadConfig{Image: "python:3.12"},
			DriverConfig: map[string]any{"kubernetes": map[string]any{"runtime_class_name": "kata"}},
			DesiredServiceLevel: &types.SandboxServiceLevel{
				Startup: &types.SandboxStartup{ReadyWithin: 30 * time.Second, MaxBurst: 4},
			},
		},
	}

	created, err := tc.Create(ctx, "default", template)
	require.NoError(t, err)
	assert.Equal(t, "gpu-kata", created.Name)
	assert.Equal(t, "default", created.Workspace)
	assert.Equal(t, uint64(1), created.ResourceVersion)
	assert.NotZero(t, created.CreatedAt)

	got, err := tc.Get(ctx, "default", "gpu-kata")
	require.NoError(t, err)
	assert.Equal(t, "python:3.12", got.Spec.Workload.Image)
	assert.Equal(t, "kata", got.Spec.DriverConfig["kubernetes"].(map[string]any)["runtime_class_name"])

	listed, err := tc.List(ctx, "default")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "gpu-kata", listed[0].Name)

	deleted, err := tc.Delete(ctx, "default", "gpu-kata")
	require.NoError(t, err)
	assert.True(t, deleted)
	_, err = tc.Get(ctx, "default", "gpu-kata")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))

	deleted, err = tc.Delete(ctx, "default", "gpu-kata")
	require.NoError(t, err)
	assert.False(t, deleted)
}

func TestSandboxTemplate_CreateAlreadyExists(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := testSandboxWorkloadTemplate("gpu-kata")
	_, err := tc.Create(ctx, "default", template)
	require.NoError(t, err)

	_, err = tc.Create(ctx, "default", template)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestSandboxTemplate_ListAllWorkspaces(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, _ = tc.Create(ctx, "default", testSandboxWorkloadTemplate("default-template"))
	_, _ = tc.Create(ctx, "team-a", testSandboxWorkloadTemplate("team-template"))

	listed, err := tc.List(ctx, "default", types.ListOptions{AllWorkspaces: true})
	require.NoError(t, err)
	assert.Len(t, listed, 2)
}

func TestSandboxTemplate_ListFiltersByLabelSelector(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, _ = tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name:   "runtime-template",
		Labels: map[string]string{"team": "runtime"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
		},
	})
	_, _ = tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name:   "batch-template",
		Labels: map[string]string{"team": "batch"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
		},
	})

	listed, err := tc.List(ctx, "default", types.ListOptions{LabelSelector: "team=runtime"})

	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "runtime-template", listed[0].Name)
}

func TestSandboxTemplate_ListRejectsNegativePagination(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, err := tc.List(ctx, "default", types.ListOptions{Limit: -1})
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))

	_, err = tc.List(ctx, "default", types.ListOptions{Offset: -1})
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestSandboxTemplate_ListAppliesPaginationAfterFiltering(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, _ = tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name:   "runtime-a",
		Labels: map[string]string{"team": "runtime"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
		},
	})
	_, _ = tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name:   "batch-a",
		Labels: map[string]string{"team": "batch"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
		},
	})
	_, _ = tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name:   "runtime-b",
		Labels: map[string]string{"team": "runtime"},
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "python:3.12"},
		},
	})

	listed, err := tc.List(ctx, "default", types.ListOptions{
		LabelSelector: "team=runtime",
		Offset:        1,
		Limit:         1,
	})

	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "runtime-b", listed[0].Name)

	listed, err = tc.List(ctx, "default", types.ListOptions{
		LabelSelector: "team=runtime",
		Offset:        2,
	})

	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestSandboxTemplate_CreateSandboxFromTemplateRequiresExistingTemplate(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	_, err := client.CreateSandboxFromTemplate(ctx, "default", "job-1", "missing", nil, nil)

	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandboxTemplate_CreateSandboxFromTemplateResolvesWorkloadAndGovernance(t *testing.T) {
	client := NewClient()
	ctx := context.Background()
	gpuCount := uint32(1)
	policy := &types.SandboxPolicy{
		Version: 1,
		NetworkPolicies: map[string]types.NetworkPolicyRule{
			"api": {Name: "api"},
		},
	}
	client.AddSandboxTemplate("default", &types.SandboxWorkloadTemplate{
		Name:            "gpu-kata",
		ResourceVersion: 7,
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{
				Image:       "registry.example.com/agent:latest",
				Environment: map[string]string{"FEATURE_FLAG": "on"},
				Resources: &types.SandboxResources{
					CPU:    "2",
					Memory: "4Gi",
					GPU:    &types.SandboxGPURequirements{Count: &gpuCount},
				},
			},
			DriverConfig: map[string]any{
				"kubernetes": map[string]any{"runtime_class_name": "kata-containers"},
			},
		},
	})

	created, err := client.CreateSandboxFromTemplate(
		ctx,
		"default",
		"job-1",
		"gpu-kata",
		&types.SandboxSpec{
			Providers: []string{"github"},
			Policy:    policy,
		},
		map[string]string{"team": "runtime"},
	)

	require.NoError(t, err)
	assert.Equal(t, "job-1", created.Name)
	assert.Equal(t, map[string]string{"team": "runtime"}, created.Labels)
	assert.Equal(t, map[string]string{"FEATURE_FLAG": "on"}, created.Spec.Environment)
	require.NotNil(t, created.Spec.Template)
	assert.Equal(t, "registry.example.com/agent:latest", created.Spec.Template.Image)
	assert.Equal(t, map[string]any{"limits": map[string]any{"cpu": "2", "memory": "4Gi"}}, created.Spec.Template.Resources)
	assert.Equal(t, "kata-containers", created.Spec.Template.DriverConfig["kubernetes"].(map[string]any)["runtime_class_name"])
	assert.True(t, created.Spec.GPU)
	require.NotNil(t, created.Spec.GPUCount)
	assert.Equal(t, uint32(1), *created.Spec.GPUCount)
	assert.Equal(t, []string{"github"}, created.Spec.Providers)
	require.NotNil(t, created.Spec.Policy)
	assert.Equal(t, uint32(1), created.Spec.Policy.Version)
	require.NotNil(t, created.CreatedFromWorkloadTemplate)
	assert.Equal(t, "gpu-kata", created.CreatedFromWorkloadTemplate.Name)
	assert.Equal(t, "7", created.CreatedFromWorkloadTemplate.ResourceVersion)
}

func TestSandboxTemplate_CreateSandboxFromTemplateRejectsWorkloadOverrides(t *testing.T) {
	client := NewClient()
	ctx := context.Background()
	gpuCount := uint32(1)
	client.AddSandboxTemplate("default", &types.SandboxWorkloadTemplate{
		Name: "gpu-kata",
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{Image: "registry.example.com/agent:latest"},
		},
	})

	tests := map[string]*types.SandboxSpec{
		"log_level": {
			LogLevel: "debug",
		},
		"environment": {
			Environment: map[string]string{"FEATURE_FLAG": "off"},
		},
		"template": {
			Template: &types.SandboxTemplate{Image: "registry.example.com/override:latest"},
		},
		"gpu_count": {
			GPUCount: &gpuCount,
		},
		"gpu": {
			GPU: true,
		},
	}

	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := client.CreateSandboxFromTemplate(ctx, "default", "job-"+name, "gpu-kata", spec, nil)

			require.Error(t, err)
			assert.True(t, types.IsInvalidArgument(err))
		})
	}

	listed, err := client.Sandboxes().List(ctx, "default")
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestSandboxTemplate_DefaultGpuRequestRoundTripsTemplate(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	created, err := tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{
		Name: "default-gpu",
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{
				Resources: &types.SandboxResources{
					GPU: &types.SandboxGPURequirements{},
				},
			},
		},
	})

	require.NoError(t, err)
	require.NotNil(t, created.Spec.Workload.Resources.GPU)
	assert.Nil(t, created.Spec.Workload.Resources.GPU.Count)

	got, err := tc.Get(ctx, "default", "default-gpu")
	require.NoError(t, err)
	require.NotNil(t, got.Spec.Workload.Resources.GPU)
	assert.Nil(t, got.Spec.Workload.Resources.GPU.Count)
}

func TestSandboxTemplate_CreateSandboxFromTemplatePreservesDefaultGPURequest(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	client.AddSandboxTemplate("default", &types.SandboxWorkloadTemplate{
		Name:            "default-gpu",
		ResourceVersion: 3,
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{
				Image: "registry.example.com/agent:latest",
				Resources: &types.SandboxResources{
					GPU: &types.SandboxGPURequirements{},
				},
			},
		},
	})

	created, err := client.CreateSandboxFromTemplate(
		ctx,
		"default",
		"job-default-gpu",
		"default-gpu",
		nil,
		nil,
	)

	require.NoError(t, err)
	assert.True(t, created.Spec.GPU)
	assert.Nil(t, created.Spec.GPUCount)
}

func TestSandboxTemplate_DeepCopy(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := &types.SandboxWorkloadTemplate{
		Name: "gpu-kata",
		Spec: types.SandboxWorkloadTemplateSpec{
			Workload: &types.SandboxWorkloadConfig{
				Image:       "python:3.12",
				Environment: map[string]string{"KEY": "value"},
			},
			DriverConfig: map[string]any{"kubernetes": map[string]any{"runtime_class_name": "kata"}},
		},
	}

	created, err := tc.Create(ctx, "default", template)
	require.NoError(t, err)

	template.Spec.Workload.Image = "mutated"
	template.Spec.Workload.Environment["KEY"] = "mutated"
	template.Spec.DriverConfig["kubernetes"].(map[string]any)["runtime_class_name"] = "mutated"
	created.Spec.Workload.Image = "mutated-return"

	got, err := tc.Get(ctx, "default", "gpu-kata")
	require.NoError(t, err)
	assert.Equal(t, "python:3.12", got.Spec.Workload.Image)
	assert.Equal(t, "value", got.Spec.Workload.Environment["KEY"])
	assert.Equal(t, "kata", got.Spec.DriverConfig["kubernetes"].(map[string]any)["runtime_class_name"])
}

func TestSandboxTemplate_CreateNil(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, err := tc.Create(ctx, "default", nil)
	require.Error(t, err)
	assert.True(t, types.IsInvalidArgument(err))
}

func TestSandboxTemplate_CreateRejectsInvalidTemplate(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()
	zeroGPUCount := uint32(0)

	tests := map[string]*types.SandboxWorkloadTemplate{
		"missing_name": {
			Spec: types.SandboxWorkloadTemplateSpec{
				Workload: &types.SandboxWorkloadConfig{Image: "registry.example.com/agent:latest"},
			},
		},
		"invalid_name": {
			Name: "Invalid_Template_Name",
			Spec: types.SandboxWorkloadTemplateSpec{
				Workload: &types.SandboxWorkloadConfig{Image: "registry.example.com/agent:latest"},
			},
		},
		"missing_workload": {
			Name: "missing-workload",
		},
		"invalid_environment": {
			Name: "invalid-env",
			Spec: types.SandboxWorkloadTemplateSpec{
				Workload: &types.SandboxWorkloadConfig{
					Image:       "registry.example.com/agent:latest",
					Environment: map[string]string{"BAD KEY": "value"},
				},
			},
		},
		"reserved_environment": {
			Name: "reserved-env",
			Spec: types.SandboxWorkloadTemplateSpec{
				Workload: &types.SandboxWorkloadConfig{
					Image:       "registry.example.com/agent:latest",
					Environment: map[string]string{"OPENSHELL_TOKEN": "value"},
				},
			},
		},
		"zero_gpu": {
			Name: "zero-gpu",
			Spec: types.SandboxWorkloadTemplateSpec{
				Workload: &types.SandboxWorkloadConfig{
					Image: "registry.example.com/agent:latest",
					Resources: &types.SandboxResources{
						GPU: &types.SandboxGPURequirements{Count: &zeroGPUCount},
					},
				},
			},
		},
	}

	for name, template := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tc.Create(ctx, "default", template)

			require.Error(t, err)
			assert.True(t, types.IsInvalidArgument(err))
		})
	}

	listed, err := tc.List(ctx, "default")
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestSandboxTemplate_ClosedReturnsUnavailable(t *testing.T) {
	store := newobjectStore(sandboxWorkloadTemplateName, copySandboxWorkloadTemplate)
	tc := newFakeSandboxTemplateClient(store, func() bool { return true })
	ctx := context.Background()

	_, err := tc.Create(ctx, "default", &types.SandboxWorkloadTemplate{Name: "gpu-kata"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
