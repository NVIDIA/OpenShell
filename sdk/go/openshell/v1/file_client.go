// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

type fileClient struct {
	client    pb.OpenShellClient
	sandboxes SandboxInterface
	transport sshTransport
}

type sshTransport interface {
	available() bool
	upload(ctx context.Context, session *pb.CreateSshSessionResponse, localPath, remotePath string) error
	download(ctx context.Context, session *pb.CreateSshSessionResponse, remotePath, localPath string) error
}

func newFileClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface) *fileClient {
	return &fileClient{
		client:    pb.NewOpenShellClient(conn),
		sandboxes: sandboxes,
		transport: &defaultSSHTransport{},
	}
}

func (f *fileClient) Upload(ctx context.Context, workspace, sandboxName string, localPath string, remotePath string) error {
	if !f.transport.available() {
		return fmt.Errorf("upload: %w", ErrTransportNotAvailable)
	}
	if sandboxName == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePath == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "remote path must not be empty"}
	}

	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local file error: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("local path is a directory, not a file: %s", localPath)
	}

	sb, err := f.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return err
	}

	session, err := f.client.CreateSshSession(ctx, &pb.CreateSshSessionRequest{
		SandboxId: sb.ID,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}

	defer func() {
		revokeCtx, revokeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer revokeCancel()
		_, _ = f.client.RevokeSshSession(revokeCtx, &pb.RevokeSshSessionRequest{
			Token: session.GetToken(),
		})
	}()

	return f.transport.upload(ctx, session, localPath, remotePath)
}

func (f *fileClient) Download(ctx context.Context, workspace, sandboxName string, remotePath string, localPath string) error {
	if !f.transport.available() {
		return fmt.Errorf("download: %w", ErrTransportNotAvailable)
	}
	if sandboxName == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if remotePath == "" {
		return &StatusError{Code: ErrorInvalidArgument, Message: "remote path must not be empty"}
	}

	sb, err := f.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return err
	}

	session, err := f.client.CreateSshSession(ctx, &pb.CreateSshSessionRequest{
		SandboxId: sb.ID,
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}

	defer func() {
		revokeCtx, revokeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer revokeCancel()
		_, _ = f.client.RevokeSshSession(revokeCtx, &pb.RevokeSshSessionRequest{
			Token: session.GetToken(),
		})
	}()

	return f.transport.download(ctx, session, remotePath, localPath)
}

type defaultSSHTransport struct{}

func (t *defaultSSHTransport) available() bool { return false }

func (t *defaultSSHTransport) upload(_ context.Context, session *pb.CreateSshSessionResponse, localPath, remotePath string) error {
	return fmt.Errorf("SSH transport to %s:%d not implemented (local: %s -> remote: %s)",
		session.GetGatewayHost(), session.GetGatewayPort(), localPath, remotePath)
}

func (t *defaultSSHTransport) download(_ context.Context, session *pb.CreateSshSessionResponse, remotePath, localPath string) error {
	return fmt.Errorf("SSH transport to %s:%d not implemented (remote: %s -> local: %s)",
		session.GetGatewayHost(), session.GetGatewayPort(), remotePath, localPath)
}
