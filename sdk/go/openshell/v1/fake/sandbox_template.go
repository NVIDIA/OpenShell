// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"slices"
	"strings"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

func sandboxWorkloadTemplateName(template *types.SandboxWorkloadTemplate) string {
	return template.Name
}

func copySandboxWorkloadTemplate(template *types.SandboxWorkloadTemplate) *types.SandboxWorkloadTemplate {
	if template == nil {
		return nil
	}
	copied := *template
	copied.Labels = copyStringMap(template.Labels)
	copied.Annotations = copyStringMap(template.Annotations)
	if template.DeletionTimestamp != nil {
		t := *template.DeletionTimestamp
		copied.DeletionTimestamp = &t
	}
	copied.Spec = copySandboxWorkloadTemplateSpec(template.Spec)
	return &copied
}

func copySandboxWorkloadTemplateSpec(spec types.SandboxWorkloadTemplateSpec) types.SandboxWorkloadTemplateSpec {
	if spec.Workload != nil {
		workload := *spec.Workload
		workload.Environment = copyStringMap(spec.Workload.Environment)
		if spec.Workload.Resources != nil {
			resources := *spec.Workload.Resources
			if spec.Workload.Resources.GPU != nil {
				gpu := *spec.Workload.Resources.GPU
				if spec.Workload.Resources.GPU.Count != nil {
					count := *spec.Workload.Resources.GPU.Count
					gpu.Count = &count
				}
				resources.GPU = &gpu
			}
			workload.Resources = &resources
		}
		spec.Workload = &workload
	}
	spec.DriverConfig = copyAnyMap(spec.DriverConfig)
	if spec.DesiredServiceLevel != nil {
		level := *spec.DesiredServiceLevel
		if spec.DesiredServiceLevel.Startup != nil {
			startup := *spec.DesiredServiceLevel.Startup
			level.Startup = &startup
		}
		spec.DesiredServiceLevel = &level
	}
	return spec
}

type fakeSandboxTemplateClient struct {
	store      *objectStore[*types.SandboxWorkloadTemplate]
	closedFunc func() bool
}

var _ v1.SandboxTemplateInterface = (*fakeSandboxTemplateClient)(nil)

func newFakeSandboxTemplateClient(
	store *objectStore[*types.SandboxWorkloadTemplate],
	closedFunc func() bool,
) *fakeSandboxTemplateClient {
	return &fakeSandboxTemplateClient{
		store:      store,
		closedFunc: closedFunc,
	}
}

func (c *fakeSandboxTemplateClient) Create(_ context.Context, workspace string, template *types.SandboxWorkloadTemplate) (*types.SandboxWorkloadTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	if template == nil {
		return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "template must not be nil"}
	}
	if err := validateSandboxWorkloadTemplate(template); err != nil {
		return nil, err
	}

	t := copySandboxWorkloadTemplate(template)
	t.Workspace = workspace
	t.CreatedAt = time.Now()
	t.ResourceVersion = 1

	return c.store.Create(workspace, t)
}

func (c *fakeSandboxTemplateClient) Get(_ context.Context, workspace, name string) (*types.SandboxWorkloadTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	return c.store.Get(workspace, name)
}

func (c *fakeSandboxTemplateClient) List(_ context.Context, workspace string, opts ...v1.ListOptions) ([]*types.SandboxWorkloadTemplate, error) {
	if c.closedFunc() {
		return nil, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	var options v1.ListOptions
	if len(opts) > 0 {
		options = opts[0]
		if options.Limit < 0 {
			return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "limit must not be negative"}
		}
		if options.Offset < 0 {
			return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "offset must not be negative"}
		}
	}
	var templates []*types.SandboxWorkloadTemplate
	if options.AllWorkspaces {
		templates = c.store.ListAll()
	} else {
		templates = c.store.List(workspace)
	}
	slices.SortFunc(templates, compareSandboxWorkloadTemplatesForList)
	templates, err := filterSandboxWorkloadTemplatesByLabelSelector(templates, options.LabelSelector)
	if err != nil {
		return nil, err
	}
	return paginateSandboxWorkloadTemplates(templates, options), nil
}

func (c *fakeSandboxTemplateClient) Delete(_ context.Context, workspace, name string) (bool, error) {
	if c.closedFunc() {
		return false, &types.StatusError{Code: types.ErrorUnavailable, Message: "client is closed"}
	}
	_, existed := c.store.DeleteAndGet(workspace, name)
	return existed, nil
}

func validateSandboxWorkloadTemplate(template *types.SandboxWorkloadTemplate) error {
	if template.Name == "" {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox_template.metadata.name is required"}
	}
	if !isDNS1123Label(template.Name) {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "template.metadata.name must be a DNS-1123 label"}
	}
	if template.Spec.Workload == nil {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "sandbox template workload is required"}
	}
	if err := validateSandboxWorkloadEnvironment(template.Spec.Workload.Environment); err != nil {
		return err
	}
	if resources := template.Spec.Workload.Resources; resources != nil && resources.GPU != nil && resources.GPU.Count != nil && *resources.GPU.Count == 0 {
		return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "gpu count must be greater than 0"}
	}
	return nil
}

func validateSandboxWorkloadEnvironment(environment map[string]string) error {
	for key := range environment {
		if !isValidEnvKey(key) {
			return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "spec.template.environment keys must match ^[A-Za-z_][A-Za-z0-9_]*$"}
		}
		if len(key) >= len("OPENSHELL_") && key[:len("OPENSHELL_")] == "OPENSHELL_" {
			return &types.StatusError{Code: types.ErrorInvalidArgument, Message: "spec.template.environment keys starting with OPENSHELL_ are reserved"}
		}
	}
	return nil
}

func filterSandboxWorkloadTemplatesByLabelSelector(
	templates []*types.SandboxWorkloadTemplate,
	selector string,
) ([]*types.SandboxWorkloadTemplate, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return templates, nil
	}
	labels, err := parseSimpleLabelSelector(selector)
	if err != nil {
		return nil, err
	}
	filtered := make([]*types.SandboxWorkloadTemplate, 0, len(templates))
	for _, template := range templates {
		if labelsMatchSelector(template.Labels, labels) {
			filtered = append(filtered, template)
		}
	}
	return filtered, nil
}

func parseSimpleLabelSelector(selector string) (map[string]string, error) {
	labels := make(map[string]string)
	for _, part := range strings.Split(selector, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "label selector must use key=value pairs"}
		}
		labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return labels, nil
}

func labelsMatchSelector(labels map[string]string, selector map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func compareSandboxWorkloadTemplatesForList(a, b *types.SandboxWorkloadTemplate) int {
	if a.CreatedAt.Before(b.CreatedAt) {
		return -1
	}
	if a.CreatedAt.After(b.CreatedAt) {
		return 1
	}
	if a.Name < b.Name {
		return -1
	}
	if a.Name > b.Name {
		return 1
	}
	if a.Workspace < b.Workspace {
		return -1
	}
	if a.Workspace > b.Workspace {
		return 1
	}
	return 0
}

func paginateSandboxWorkloadTemplates(
	templates []*types.SandboxWorkloadTemplate,
	options v1.ListOptions,
) []*types.SandboxWorkloadTemplate {
	if options.Offset >= len(templates) {
		return templates[:0]
	}
	templates = templates[options.Offset:]
	if options.Limit > 0 && options.Limit < len(templates) {
		return templates[:options.Limit]
	}
	return templates
}

func isDNS1123Label(name string) bool {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	previousHyphen := false
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if !isASCIIDigit(b) && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

func isValidEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		b := key[i]
		if i == 0 && b != '_' && !isASCIIAlpha(b) {
			return false
		}
		if i > 0 && b != '_' && !isASCIIAlpha(b) && !isASCIIDigit(b) {
			return false
		}
	}
	return true
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
