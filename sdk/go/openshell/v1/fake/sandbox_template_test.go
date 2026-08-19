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
	store := newobjectStore(sandboxTemplateName, copySandboxTemplatePtr)
	return newFakeSandboxTemplateClient(store, func() bool { return false })
}

func TestSandboxTemplate_CreateGetListDelete(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := &types.SandboxTemplate{
		Name:   "gpu-kata",
		Labels: map[string]string{"team": "platform"},
		Spec: types.SandboxTemplateSpec{
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

	err = tc.Delete(ctx, "default", "gpu-kata")
	require.NoError(t, err)
	_, err = tc.Get(ctx, "default", "gpu-kata")
	require.Error(t, err)
	assert.True(t, types.IsNotFound(err))
}

func TestSandboxTemplate_CreateAlreadyExists(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := &types.SandboxTemplate{Name: "gpu-kata"}
	_, err := tc.Create(ctx, "default", template)
	require.NoError(t, err)

	_, err = tc.Create(ctx, "default", template)
	require.Error(t, err)
	assert.True(t, types.IsAlreadyExists(err))
}

func TestSandboxTemplate_ListAllWorkspaces(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	_, _ = tc.Create(ctx, "default", &types.SandboxTemplate{Name: "default-template"})
	_, _ = tc.Create(ctx, "team-a", &types.SandboxTemplate{Name: "team-template"})

	listed, err := tc.List(ctx, "default", types.ListOptions{AllWorkspaces: true})
	require.NoError(t, err)
	assert.Len(t, listed, 2)
}

func TestSandboxTemplate_DeepCopy(t *testing.T) {
	tc := newTestSandboxTemplateClient()
	ctx := context.Background()

	template := &types.SandboxTemplate{
		Name: "gpu-kata",
		Spec: types.SandboxTemplateSpec{
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

func TestSandboxTemplate_ClosedReturnsUnavailable(t *testing.T) {
	store := newobjectStore(sandboxTemplateName, copySandboxTemplatePtr)
	tc := newFakeSandboxTemplateClient(store, func() bool { return true })
	ctx := context.Background()

	_, err := tc.Create(ctx, "default", &types.SandboxTemplate{Name: "gpu-kata"})
	require.Error(t, err)
	assert.True(t, types.IsUnavailable(err))
}
