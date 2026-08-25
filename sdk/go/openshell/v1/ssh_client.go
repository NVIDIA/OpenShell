// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
)

const sshCleanupTimeout = 5 * time.Second

type sshClient struct {
	client    pb.OpenShellClient
	sandboxes SandboxInterface
}

func newSSHClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface) *sshClient {
	return &sshClient{
		client:    pb.NewOpenShellClient(conn),
		sandboxes: sandboxes,
	}
}

func (s *sshClient) CreateSession(ctx context.Context, _, sandboxID string) (*SSHSession, error) {
	resp, err := s.client.CreateSshSession(ctx, &pb.CreateSshSessionRequest{
		SandboxId: sandboxID,
	})
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}
	return converter.SSHSessionFromProto(resp), nil
}

func (s *sshClient) RevokeSession(ctx context.Context, _, token string) (bool, error) {
	resp, err := s.client.RevokeSshSession(ctx, &pb.RevokeSshSessionRequest{
		Token: token,
	})
	if err != nil {
		return false, converter.FromGRPCError(err)
	}
	return resp.GetRevoked(), nil
}

func (s *sshClient) Tunnel(ctx context.Context, workspace, sandboxName string, port uint32, opts ...TunnelOption) (io.ReadWriteCloser, error) {
	if sandboxName == "" {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: "sandbox name must not be empty",
		}
	}
	if port == 0 || port > 65535 {
		return nil, &StatusError{
			Code:    ErrorInvalidArgument,
			Message: fmt.Sprintf("port must be in range 1-65535, got %d", port),
		}
	}

	var cfg tunnelConfig
	for _, o := range opts {
		o(&cfg)
	}

	sandbox, err := s.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	session, err := s.CreateSession(ctx, workspace, sandbox.ID)
	if err != nil {
		return nil, err
	}

	revokeSession := true
	defer func() {
		if revokeSession {
			s.revokeSessionForCleanup(workspace, session.Token)
		}
	}()

	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := s.client.ForwardTcp(streamCtx)
	if err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	initFrame := &pb.TcpForwardFrame{
		Payload: &pb.TcpForwardFrame_Init{
			Init: &pb.TcpForwardInit{
				SandboxId:          sandbox.ID,
				ServiceId:          cfg.serviceID,
				AuthorizationToken: session.Token,
				Target: &pb.TcpForwardInit_Ssh{
					Ssh: &pb.SshRelayTarget{},
				},
			},
		},
	}

	if err := stream.Send(initFrame); err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	conn := &tcpForwardConn{
		stream:    stream,
		streamCtx: streamCtx,
		cancel:    cancel,
		dataCh:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	go conn.readLoop()

	revokeSession = false

	t := &sshTunnel{
		tcpForwardConn: conn,
		revokeFunc: func() {
			s.revokeSessionForCleanup(workspace, session.Token)
		},
	}

	// Auto-revoke the SSH session when the parent context is cancelled.
	// The done channel closes after readLoop exits (stream fully drained),
	// so Close() won't race with an active stream.
	go func() {
		<-conn.done
		_ = t.Close()
	}()

	return t, nil
}

func (s *sshClient) revokeSessionForCleanup(workspace, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), sshCleanupTimeout)
	defer cancel()
	_, _ = s.RevokeSession(ctx, workspace, token)
}

type sshTunnel struct {
	*tcpForwardConn
	revokeFunc func()
	closeOnce  sync.Once
	closeErr   error
}

func (t *sshTunnel) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.tcpForwardConn.Close()
		t.revokeFunc()
	})
	return t.closeErr
}
