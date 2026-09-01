// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	internalgrpc "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/grpc"
	"google.golang.org/grpc"
)

// Config holds all settings needed to create a Client.
type Config = types.Config

// ClientInterface defines the top-level SDK surface.
type ClientInterface interface {
	Sandboxes() SandboxInterface
	SandboxTemplates() SandboxTemplateInterface
	CreateSandboxFromTemplate(ctx context.Context, workspace, name, templateName string, spec *SandboxSpec, labels map[string]string, opts ...CreateOptions) (*Sandbox, error)
	Providers() ProviderInterface
	Services() ServiceInterface
	Exec() ExecInterface
	Files() FileInterface
	Health() HealthInterface
	SSH() SSHInterface
	TCP() TCPInterface
	Config() ConfigInterface
	Policy() PolicyInterface
	Workspaces() WorkspaceInterface
	Inference() InferenceInterface
	Close() error
}

// SandboxInterface is defined in sandbox.go

// ProviderInterface is defined in provider.go

// ExecInterface is defined in exec.go

// FileInterface is defined in file.go

// Client implements ClientInterface. It holds a gRPC connection and provides
// sub-client accessors following the Kubernetes client-go pattern.
type Client struct {
	conn   *grpc.ClientConn
	config Config

	closeOnce sync.Once
	closeErr  error

	sandboxes      SandboxInterface
	templateCreate SandboxTemplateCreateInterface
	templates      SandboxTemplateInterface
	providers      ProviderInterface
	services       ServiceInterface
	exec           ExecInterface
	files          FileInterface
	health         HealthInterface
	ssh            SSHInterface
	tcp            TCPInterface
	cfg            ConfigInterface
	policy         PolicyInterface
	workspaces     WorkspaceInterface
	inference      InferenceInterface
}

// NewClient creates a new SDK client connected to the given gateway.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "address must not be empty"}
	}

	if cfg.Auth == nil {
		cfg.Auth = NoAuth()
	}

	var tlsParams *internalgrpc.TLSParams
	if cfg.TLS != nil {
		tlsParams = &internalgrpc.TLSParams{
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
			CAFile:   cfg.TLS.CAFile,
			Insecure: cfg.TLS.Insecure,
		}
	}

	conn, err := internalgrpc.NewConnection(cfg.Address, tlsParams, cfg.Auth)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:   conn,
		config: cfg,
	}

	sandboxes := newSandboxClient(conn)
	c.sandboxes = sandboxes
	c.templateCreate = sandboxes
	c.templates = newSandboxTemplateClient(conn)
	c.providers = newProviderClient(conn)
	c.services = newServiceClient(conn)
	c.exec = newExecClient(conn, c.sandboxes)
	c.files = newFileClient(conn, c.sandboxes)
	c.health = newHealthClient(conn)
	c.ssh = newSSHClient(conn, c.sandboxes)
	c.tcp = newTCPClient(conn, c.sandboxes, c.ssh)
	c.cfg = newConfigClient(conn, c.sandboxes)
	c.policy = newPolicyClient(conn)
	c.workspaces = newWorkspaceClient(conn)
	c.inference = newInferenceClient(conn)

	return c, nil
}

// Sandboxes returns the sandbox sub-client.
func (c *Client) Sandboxes() SandboxInterface { return c.sandboxes }

// SandboxTemplates returns the reusable sandbox template sub-client.
func (c *Client) SandboxTemplates() SandboxTemplateInterface { return c.templates }

// CreateSandboxFromTemplate creates a sandbox from a named workload template
// without changing the legacy Sandboxes() interface.
func (c *Client) CreateSandboxFromTemplate(ctx context.Context, workspace, name, templateName string, spec *SandboxSpec, labels map[string]string, opts ...CreateOptions) (*Sandbox, error) {
	return c.templateCreate.CreateFromTemplate(ctx, workspace, name, templateName, spec, labels, opts...)
}

// Providers returns the provider sub-client.
func (c *Client) Providers() ProviderInterface { return c.providers }

// Services returns the service sub-client.
func (c *Client) Services() ServiceInterface { return c.services }

// Exec returns the exec sub-client.
func (c *Client) Exec() ExecInterface { return c.exec }

// Files returns the file sub-client.
func (c *Client) Files() FileInterface { return c.files }

// Health returns the health sub-client.
func (c *Client) Health() HealthInterface { return c.health }

// SSH returns the SSH session sub-client.
func (c *Client) SSH() SSHInterface { return c.ssh }

// TCP returns the TCP port forwarding sub-client.
func (c *Client) TCP() TCPInterface { return c.tcp }

// Config returns the configuration sub-client.
func (c *Client) Config() ConfigInterface { return c.cfg }

// Policy returns the policy management sub-client.
func (c *Client) Policy() PolicyInterface { return c.policy }

// Workspaces returns the workspace management sub-client.
func (c *Client) Workspaces() WorkspaceInterface { return c.workspaces }

// Inference returns the inference route management sub-client.
func (c *Client) Inference() InferenceInterface { return c.inference }

// Close closes the underlying gRPC connection. Safe to call multiple times.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}
