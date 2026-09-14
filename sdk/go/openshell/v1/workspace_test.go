// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"testing"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mockWorkspaceServer struct {
	pb.UnimplementedOpenShellServer

	createResp         *pb.CreateWorkspaceResponse
	getResp            *pb.GetWorkspaceResponse
	listResp           *pb.ListWorkspacesResponse
	deleteResp         *pb.DeleteWorkspaceResponse
	addMemberResp      *pb.AddWorkspaceMemberResponse
	removeMemberResp   *pb.RemoveWorkspaceMemberResponse
	listMembersResp    *pb.ListWorkspaceMembersResponse
	err                error
	lastCreateReq      *pb.CreateWorkspaceRequest
	lastListReq        *pb.ListWorkspacesRequest
	lastAddMemberReq   *pb.AddWorkspaceMemberRequest
	lastListMembersReq *pb.ListWorkspaceMembersRequest
}

func (s *mockWorkspaceServer) CreateWorkspace(_ context.Context, req *pb.CreateWorkspaceRequest) (*pb.CreateWorkspaceResponse, error) {
	s.lastCreateReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.createResp, nil
}

func (s *mockWorkspaceServer) GetWorkspace(_ context.Context, _ *pb.GetWorkspaceRequest) (*pb.GetWorkspaceResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.getResp, nil
}

func (s *mockWorkspaceServer) ListWorkspaces(_ context.Context, req *pb.ListWorkspacesRequest) (*pb.ListWorkspacesResponse, error) {
	s.lastListReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.listResp, nil
}

func (s *mockWorkspaceServer) DeleteWorkspace(_ context.Context, _ *pb.DeleteWorkspaceRequest) (*pb.DeleteWorkspaceResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.deleteResp, nil
}

func (s *mockWorkspaceServer) AddWorkspaceMember(_ context.Context, req *pb.AddWorkspaceMemberRequest) (*pb.AddWorkspaceMemberResponse, error) {
	s.lastAddMemberReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.addMemberResp, nil
}

func (s *mockWorkspaceServer) RemoveWorkspaceMember(_ context.Context, _ *pb.RemoveWorkspaceMemberRequest) (*pb.RemoveWorkspaceMemberResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.removeMemberResp, nil
}

func (s *mockWorkspaceServer) ListWorkspaceMembers(_ context.Context, req *pb.ListWorkspaceMembersRequest) (*pb.ListWorkspaceMembersResponse, error) {
	s.lastListMembersReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.listMembersResp, nil
}

func newMockWorkspaceServer(mock *mockWorkspaceServer) (*grpc.ClientConn, func()) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterOpenShellServer(srv, mock)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		panic("grpc.NewClient failed: " + err.Error())
	}

	return conn, func() {
		_ = conn.Close()
		srv.Stop()
	}
}

func testWorkspace() *dm.Workspace {
	return &dm.Workspace{
		Metadata: &dm.ObjectMeta{
			Id:              "ws-1",
			Name:            "test-ws",
			CreatedAtMs:     1700000000000,
			Labels:          map[string]string{"team": "platform"},
			ResourceVersion: 1,
		},
		Status: &dm.WorkspaceStatus{
			Phase: dm.WorkspacePhase_WORKSPACE_PHASE_ACTIVE,
		},
	}
}

func TestWorkspaceCreate_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		createResp: &pb.CreateWorkspaceResponse{Workspace: testWorkspace()},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	ws, err := wc.Create(context.Background(), "test-ws", map[string]string{"team": "platform"})

	require.NoError(t, err)
	require.NotNil(t, ws)
	assert.Equal(t, "test-ws", ws.Name)
	assert.Equal(t, WorkspaceActive, ws.Phase)
	assert.Equal(t, map[string]string{"team": "platform"}, ws.Labels)
	assert.Equal(t, "test-ws", mock.lastCreateReq.GetName())
}

func TestWorkspaceCreate_EmptyName(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.Create(context.Background(), "", nil)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestWorkspaceCreate_AlreadyExists(t *testing.T) {
	mock := &mockWorkspaceServer{
		err: status.Error(codes.AlreadyExists, "workspace already exists"),
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.Create(context.Background(), "existing-ws", nil)

	require.Error(t, err)
	assert.True(t, IsAlreadyExists(err))
}

func TestWorkspaceGet_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		getResp: &pb.GetWorkspaceResponse{Workspace: testWorkspace()},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	ws, err := wc.Get(context.Background(), "test-ws")

	require.NoError(t, err)
	require.NotNil(t, ws)
	assert.Equal(t, "test-ws", ws.Name)
}

func TestWorkspaceGet_EmptyName(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.Get(context.Background(), "")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestWorkspaceGet_NotFound(t *testing.T) {
	mock := &mockWorkspaceServer{
		err: status.Error(codes.NotFound, "workspace not found"),
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.Get(context.Background(), "missing-ws")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestWorkspaceList_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		listResp: &pb.ListWorkspacesResponse{
			Workspaces: []*dm.Workspace{testWorkspace()},
		},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	workspaces, err := wc.List(context.Background())

	require.NoError(t, err)
	require.Len(t, workspaces, 1)
	assert.Equal(t, "test-ws", workspaces[0].Name)
}

func TestWorkspaceList_WithOptions(t *testing.T) {
	mock := &mockWorkspaceServer{
		listResp: &pb.ListWorkspacesResponse{},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.List(context.Background(), ListOptions{
		Limit:         10,
		Offset:        5,
		LabelSelector: "team=platform",
	})

	require.NoError(t, err)
	assert.Equal(t, uint32(10), mock.lastListReq.GetLimit())
	assert.Equal(t, uint32(5), mock.lastListReq.GetOffset())
	assert.Equal(t, "team=platform", mock.lastListReq.GetLabelSelector())
}

func TestWorkspaceDelete_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		deleteResp: &pb.DeleteWorkspaceResponse{Deleted: true},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.Delete(context.Background(), "test-ws")

	require.NoError(t, err)
}

func TestWorkspaceDelete_EmptyName(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.Delete(context.Background(), "")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestWorkspaceDelete_NotFound(t *testing.T) {
	mock := &mockWorkspaceServer{
		err: status.Error(codes.NotFound, "workspace not found"),
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.Delete(context.Background(), "missing-ws")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// --- Member management tests ---

func testMember() *pb.WorkspaceMember {
	return &pb.WorkspaceMember{
		Metadata: &dm.ObjectMeta{
			Id:              "mem-1",
			Name:            "member-auto",
			CreatedAtMs:     1700000000000,
			ResourceVersion: 1,
		},
		PrincipalSubject: "user@example.com",
		Role:             pb.WorkspaceRole_WORKSPACE_ROLE_ADMIN,
	}
}

func TestAddMember_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		addMemberResp: &pb.AddWorkspaceMemberResponse{Member: testMember()},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	m, err := wc.AddMember(context.Background(), "test-ws", "user@example.com", WorkspaceRoleAdmin)

	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "user@example.com", m.PrincipalSubject)
	assert.Equal(t, WorkspaceRoleAdmin, m.Role)
	assert.Equal(t, "test-ws", mock.lastAddMemberReq.GetWorkspace())
	assert.Equal(t, "user@example.com", mock.lastAddMemberReq.GetPrincipalSubject())
}

func TestAddMember_EmptyWorkspace(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.AddMember(context.Background(), "", "user@example.com", WorkspaceRoleAdmin)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestAddMember_EmptySubject(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.AddMember(context.Background(), "test-ws", "", WorkspaceRoleAdmin)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestAddMember_InvalidRole(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.AddMember(context.Background(), "test-ws", "user@example.com", WorkspaceRole("invalid"))

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestAddMember_AlreadyExists(t *testing.T) {
	mock := &mockWorkspaceServer{
		err: status.Error(codes.AlreadyExists, "member already exists"),
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.AddMember(context.Background(), "test-ws", "user@example.com", WorkspaceRoleUser)

	require.Error(t, err)
	assert.True(t, IsAlreadyExists(err))
}

func TestRemoveMember_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		removeMemberResp: &pb.RemoveWorkspaceMemberResponse{Removed: true},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.RemoveMember(context.Background(), "test-ws", "user@example.com")

	require.NoError(t, err)
}

func TestRemoveMember_EmptyWorkspace(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.RemoveMember(context.Background(), "", "user@example.com")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestRemoveMember_EmptySubject(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.RemoveMember(context.Background(), "test-ws", "")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestRemoveMember_NotFound(t *testing.T) {
	mock := &mockWorkspaceServer{
		err: status.Error(codes.NotFound, "member not found"),
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	err := wc.RemoveMember(context.Background(), "test-ws", "missing@example.com")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestListMembers_Success(t *testing.T) {
	mock := &mockWorkspaceServer{
		listMembersResp: &pb.ListWorkspaceMembersResponse{
			Members: []*pb.WorkspaceMember{testMember()},
		},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	members, err := wc.ListMembers(context.Background(), "test-ws")

	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "user@example.com", members[0].PrincipalSubject)
}

func TestListMembers_EmptyWorkspace(t *testing.T) {
	mock := &mockWorkspaceServer{}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.ListMembers(context.Background(), "")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestListMembers_WithOptions(t *testing.T) {
	mock := &mockWorkspaceServer{
		listMembersResp: &pb.ListWorkspaceMembersResponse{},
	}
	conn, cleanup := newMockWorkspaceServer(mock)
	defer cleanup()

	wc := newWorkspaceClient(conn)
	_, err := wc.ListMembers(context.Background(), "test-ws", ListOptions{Limit: 5, Offset: 2})

	require.NoError(t, err)
	assert.Equal(t, uint32(5), mock.lastListMembersReq.GetLimit())
	assert.Equal(t, uint32(2), mock.lastListMembersReq.GetOffset())
}
