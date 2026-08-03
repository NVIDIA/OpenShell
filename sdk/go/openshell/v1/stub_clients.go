// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"net"
)

func stubError(method string) error {
	return &StatusError{
		Code:    ErrorUnimplemented,
		Message: method + " not yet available - see https://github.com/NVIDIA/OpenShell/issues/2270",
	}
}

// stubExec implements ExecInterface as a placeholder.
type stubExec struct{}

func (s *stubExec) Run(_ context.Context, _, _ string, _ []string, _ ...ExecOptions) (*ExecResult, error) {
	return nil, stubError("Exec.Run")
}
func (s *stubExec) Stream(_ context.Context, _, _ string, _ []string, _ ...ExecOptions) (ExecStream, error) {
	return nil, stubError("Exec.Stream")
}
func (s *stubExec) Interactive(_ context.Context, _, _ string, _ []string, _, _ uint32, _ ...ExecOptions) (InteractiveSession, error) {
	return nil, stubError("Exec.Interactive")
}

// stubFiles implements FileInterface as a placeholder.
type stubFiles struct{}

func (s *stubFiles) Upload(_ context.Context, _, _, _, _ string) error {
	return stubError("Files.Upload")
}
func (s *stubFiles) Download(_ context.Context, _, _, _, _ string) error {
	return stubError("Files.Download")
}

// stubHealth implements HealthInterface as a placeholder.
type stubHealth struct{}

func (s *stubHealth) Check(_ context.Context) (*HealthResult, error) {
	return nil, stubError("Health.Check")
}

// stubProviders implements ProviderInterface as a placeholder.
type stubProviders struct{}

func (s *stubProviders) Create(_ context.Context, _ string, _ *Provider) (*Provider, error) {
	return nil, stubError("Providers.Create")
}
func (s *stubProviders) Get(_ context.Context, _, _ string) (*Provider, error) {
	return nil, stubError("Providers.Get")
}
func (s *stubProviders) List(_ context.Context, _ string, _ ...ListOptions) ([]*Provider, error) {
	return nil, stubError("Providers.List")
}
func (s *stubProviders) Update(_ context.Context, _ string, _ *Provider) (*Provider, error) {
	return nil, stubError("Providers.Update")
}
func (s *stubProviders) Delete(_ context.Context, _, _ string) error {
	return stubError("Providers.Delete")
}
func (s *stubProviders) Ensure(_ context.Context, _ string, _ *Provider) (*Provider, error) {
	return nil, stubError("Providers.Ensure")
}
func (s *stubProviders) Profiles() ProfileInterface { return &stubProfiles{} }
func (s *stubProviders) Refresh() RefreshInterface  { return &stubRefresh{} }

// stubProfiles implements ProfileInterface as a placeholder.
type stubProfiles struct{}

func (s *stubProfiles) List(_ context.Context, _ string, _ ...ListOptions) ([]*ProviderProfile, error) {
	return nil, stubError("Profiles.List")
}
func (s *stubProfiles) Get(_ context.Context, _, _ string) (*ProviderProfile, error) {
	return nil, stubError("Profiles.Get")
}
func (s *stubProfiles) Import(_ context.Context, _ string, _ []ProfileImportItem) (*ImportResult, error) {
	return nil, stubError("Profiles.Import")
}
func (s *stubProfiles) Update(_ context.Context, _, _ string, _ uint64, _ ProfileImportItem) (*UpdateResult, error) {
	return nil, stubError("Profiles.Update")
}
func (s *stubProfiles) Lint(_ context.Context, _ string, _ []ProfileImportItem) (*LintResult, error) {
	return nil, stubError("Profiles.Lint")
}
func (s *stubProfiles) Delete(_ context.Context, _, _ string) (bool, error) {
	return false, stubError("Profiles.Delete")
}

// stubRefresh implements RefreshInterface as a placeholder.
type stubRefresh struct{}

func (s *stubRefresh) GetStatus(_ context.Context, _, _, _ string) ([]*RefreshStatus, error) {
	return nil, stubError("Refresh.GetStatus")
}
func (s *stubRefresh) Configure(_ context.Context, _ string, _ *RefreshConfig) (*RefreshStatus, error) {
	return nil, stubError("Refresh.Configure")
}
func (s *stubRefresh) Rotate(_ context.Context, _, _, _ string) (*RefreshStatus, error) {
	return nil, stubError("Refresh.Rotate")
}
func (s *stubRefresh) Delete(_ context.Context, _, _, _ string) (bool, error) {
	return false, stubError("Refresh.Delete")
}

// stubServices implements ServiceInterface as a placeholder.
type stubServices struct{}

func (s *stubServices) Expose(_ context.Context, _, _, _ string, _ uint32, _ bool) (*ServiceEndpoint, error) {
	return nil, stubError("Services.Expose")
}
func (s *stubServices) Get(_ context.Context, _, _, _ string) (*ServiceEndpoint, error) {
	return nil, stubError("Services.Get")
}
func (s *stubServices) List(_ context.Context, _, _ string, _ ...ListOptions) ([]*ServiceEndpoint, error) {
	return nil, stubError("Services.List")
}
func (s *stubServices) Delete(_ context.Context, _, _, _ string) error {
	return stubError("Services.Delete")
}

// stubSSH implements SSHInterface as a placeholder.
type stubSSH struct{}

func (s *stubSSH) CreateSession(_ context.Context, _, _ string) (*SSHSession, error) {
	return nil, stubError("SSH.CreateSession")
}
func (s *stubSSH) RevokeSession(_ context.Context, _, _ string) (bool, error) {
	return false, stubError("SSH.RevokeSession")
}
func (s *stubSSH) Tunnel(_ context.Context, _, _ string, _ uint32, _ ...TunnelOption) (io.ReadWriteCloser, error) {
	return nil, stubError("SSH.Tunnel")
}

// stubTCP implements TCPInterface as a placeholder.
type stubTCP struct{}

func (s *stubTCP) Forward(_ context.Context, _, _ string, _ uint32, _ ...ForwardOption) (io.ReadWriteCloser, error) {
	return nil, stubError("TCP.Forward")
}
func (s *stubTCP) Listen(_ context.Context, _, _ string, _, _ uint32, _ ...ListenOption) (net.Listener, error) {
	return nil, stubError("TCP.Listen")
}

// stubConfig implements ConfigInterface as a placeholder.
type stubConfig struct{}

func (s *stubConfig) GetSandbox(_ context.Context, _, _ string) (*SandboxConfig, error) {
	return nil, stubError("Config.GetSandbox")
}
func (s *stubConfig) GetGateway(_ context.Context) (*GatewayConfig, error) {
	return nil, stubError("Config.GetGateway")
}
func (s *stubConfig) Update(_ context.Context, _ string, _ *ConfigUpdate) (*ConfigUpdateResult, error) {
	return nil, stubError("Config.Update")
}

// stubPolicy implements PolicyInterface as a placeholder.
type stubPolicy struct{}

func (s *stubPolicy) GetDraft(_ context.Context, _, _ string, _ ...GetDraftOption) (*DraftPolicy, error) {
	return nil, stubError("Policy.GetDraft")
}
func (s *stubPolicy) ApproveDraftChunk(_ context.Context, _, _, _ string) (*ApproveResult, error) {
	return nil, stubError("Policy.ApproveDraftChunk")
}
func (s *stubPolicy) RejectDraftChunk(_ context.Context, _, _, _, _ string) error {
	return stubError("Policy.RejectDraftChunk")
}
func (s *stubPolicy) ApproveAllDraftChunks(_ context.Context, _, _ string, _ ...ApproveAllOption) (*ApproveAllResult, error) {
	return nil, stubError("Policy.ApproveAllDraftChunks")
}
func (s *stubPolicy) ClearDraftChunks(_ context.Context, _, _ string) (*ClearResult, error) {
	return nil, stubError("Policy.ClearDraftChunks")
}
func (s *stubPolicy) GetDraftHistory(_ context.Context, _, _ string) ([]DraftHistoryEntry, error) {
	return nil, stubError("Policy.GetDraftHistory")
}
func (s *stubPolicy) GetStatus(_ context.Context, _, _ string, _ ...GetStatusOption) (*PolicyStatusResult, error) {
	return nil, stubError("Policy.GetStatus")
}
func (s *stubPolicy) List(_ context.Context, _ string, _ ...ListPolicyOption) ([]SandboxPolicyRevision, error) {
	return nil, stubError("Policy.List")
}
func (s *stubPolicy) EditDraftChunk(_ context.Context, _, _, _ string, _ *NetworkPolicyRule) error {
	return stubError("Policy.EditDraftChunk")
}
func (s *stubPolicy) UndoDraftChunk(_ context.Context, _, _, _ string) (*UndoResult, error) {
	return nil, stubError("Policy.UndoDraftChunk")
}
