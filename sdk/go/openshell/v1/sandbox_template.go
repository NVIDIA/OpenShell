// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import "context"

// SandboxTemplateInterface defines CRUD operations on sandbox templates.
type SandboxTemplateInterface interface {
	Create(ctx context.Context, workspace string, template *SandboxTemplate) (*SandboxTemplate, error)
	Get(ctx context.Context, workspace, name string) (*SandboxTemplate, error)
	List(ctx context.Context, workspace string, opts ...ListOptions) ([]*SandboxTemplate, error)
	Delete(ctx context.Context, workspace, name string) error
}
