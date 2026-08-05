// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

const bufSize = 1024 * 1024

type mockSandboxServer struct {
	pb.UnimplementedOpenShellServer
	mu                 sync.Mutex
	sandboxes          map[string]*pb.Sandbox
	providers          map[string][]*dm.Provider
	createErr          error
	getErr             error
	listErr            error
	deleteErr          error
	attachErr          error
	detachErr          error
	listProvErr        error
	watchEvents        []*pb.SandboxStreamEvent
	watchErr           error
	watchPostEventsErr error
	watchKeepOpen      chan struct{}           // if non-nil, WatchSandbox blocks after sending events until closed
	watchRequest       *pb.WatchSandboxRequest // recorded request

	// GetLogs fields
	getLogsResp    *pb.GetSandboxLogsResponse
	getLogsErr     error
	getLogsRequest *pb.GetSandboxLogsRequest // recorded request
}

func newMockSandboxServer() *mockSandboxServer {
	return &mockSandboxServer{
		sandboxes: make(map[string]*pb.Sandbox),
		providers: make(map[string][]*dm.Provider),
	}
}

func (s *mockSandboxServer) CreateSandbox(_ context.Context, req *pb.CreateSandboxRequest) (*pb.SandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return nil, s.createErr
	}
	sb := &pb.Sandbox{
		Metadata: &dm.ObjectMeta{
			Id:              "sb-" + req.GetName(),
			Name:            req.GetName(),
			CreatedAtMs:     1700000000000,
			Labels:          req.GetLabels(),
			ResourceVersion: 1,
		},
		Spec:   req.GetSpec(),
		Status: &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	s.sandboxes[req.GetName()] = sb
	return &pb.SandboxResponse{Sandbox: sb}, nil
}

func (s *mockSandboxServer) GetSandbox(_ context.Context, req *pb.GetSandboxRequest) (*pb.SandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	sb, ok := s.sandboxes[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "sandbox %q not found", req.GetName())
	}
	cloned := proto.Clone(sb).(*pb.Sandbox)
	return &pb.SandboxResponse{Sandbox: cloned}, nil
}

func (s *mockSandboxServer) setPhase(name string, phase pb.SandboxPhase) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sb, ok := s.sandboxes[name]; ok {
		sb.Status.Phase = phase
	}
}

func (s *mockSandboxServer) ListSandboxes(_ context.Context, _ *pb.ListSandboxesRequest) (*pb.ListSandboxesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	var list []*pb.Sandbox
	for _, sb := range s.sandboxes {
		list = append(list, sb)
	}
	return &pb.ListSandboxesResponse{Sandboxes: list}, nil
}

func (s *mockSandboxServer) DeleteSandbox(_ context.Context, req *pb.DeleteSandboxRequest) (*pb.DeleteSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	_, ok := s.sandboxes[req.GetName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "sandbox %q not found", req.GetName())
	}
	delete(s.sandboxes, req.GetName())
	return &pb.DeleteSandboxResponse{Deleted: true}, nil
}

func (s *mockSandboxServer) AttachSandboxProvider(_ context.Context, req *pb.AttachSandboxProviderRequest) (*pb.AttachSandboxProviderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attachErr != nil {
		return nil, s.attachErr
	}
	sb, ok := s.sandboxes[req.GetSandboxName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "sandbox %q not found", req.GetSandboxName())
	}
	sb.Spec.Providers = append(sb.Spec.Providers, req.GetProviderName())
	return &pb.AttachSandboxProviderResponse{Sandbox: sb, Attached: true}, nil
}

func (s *mockSandboxServer) DetachSandboxProvider(_ context.Context, req *pb.DetachSandboxProviderRequest) (*pb.DetachSandboxProviderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detachErr != nil {
		return nil, s.detachErr
	}
	sb, ok := s.sandboxes[req.GetSandboxName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "sandbox %q not found", req.GetSandboxName())
	}
	return &pb.DetachSandboxProviderResponse{Sandbox: sb, Detached: true}, nil
}

func (s *mockSandboxServer) ListSandboxProviders(_ context.Context, req *pb.ListSandboxProvidersRequest) (*pb.ListSandboxProvidersResponse, error) {
	if s.listProvErr != nil {
		return nil, s.listProvErr
	}
	provs := s.providers[req.GetSandboxName()]
	return &pb.ListSandboxProvidersResponse{Providers: provs}, nil
}

func (s *mockSandboxServer) WatchSandbox(req *pb.WatchSandboxRequest, stream grpc.ServerStreamingServer[pb.SandboxStreamEvent]) error {
	s.mu.Lock()
	s.watchRequest = req
	s.mu.Unlock()
	if s.watchErr != nil {
		return s.watchErr
	}
	s.mu.Lock()
	events := make([]*pb.SandboxStreamEvent, len(s.watchEvents))
	copy(events, s.watchEvents)
	keepOpen := s.watchKeepOpen
	s.mu.Unlock()
	for _, ev := range events {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	if s.watchPostEventsErr != nil {
		return s.watchPostEventsErr
	}
	// If watchKeepOpen is set, block until it is closed (simulates long-running stream)
	if keepOpen != nil {
		<-keepOpen
	}
	return nil
}

func (s *mockSandboxServer) GetSandboxLogs(_ context.Context, req *pb.GetSandboxLogsRequest) (*pb.GetSandboxLogsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getLogsRequest = req
	if s.getLogsErr != nil {
		return nil, s.getLogsErr
	}
	if s.getLogsResp != nil {
		return s.getLogsResp, nil
	}
	return &pb.GetSandboxLogsResponse{}, nil
}

func setupSandboxTest(t *testing.T, mock *mockSandboxServer) (*sandboxClient, func()) {
	t.Helper()
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
	require.NoError(t, err)

	return newSandboxClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// --- T029: Sandbox CRUD tests ---

func TestSandboxCreate(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	spec := &SandboxSpec{
		LogLevel:    "debug",
		Environment: map[string]string{"FOO": "bar"},
		Providers:   []string{"claude"},
	}
	labels := map[string]string{"env": "dev"}

	result, err := client.Create(context.Background(), "default", "my-sandbox", spec, labels)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "my-sandbox", result.Name)
	assert.Equal(t, "sb-my-sandbox", result.ID)
	assert.Equal(t, map[string]string{"env": "dev"}, result.Labels)
	assert.Equal(t, SandboxProvisioning, result.Status.Phase)
}

func TestSandboxCreate_AlreadyExists(t *testing.T) {
	mock := newMockSandboxServer()
	mock.createErr = status.Error(codes.AlreadyExists, "sandbox already exists")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.Create(context.Background(), "default", "dup", &SandboxSpec{}, nil)

	require.Error(t, err)
	assert.True(t, IsAlreadyExists(err))
}

func TestSandboxGet(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["existing"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-1", Name: "existing", ResourceVersion: 5},
		Spec:     &pb.SandboxSpec{LogLevel: "info"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.Get(context.Background(), "default", "existing")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "existing", result.Name)
	assert.Equal(t, "sb-1", result.ID)
	assert.Equal(t, uint64(5), result.ResourceVersion)
	assert.Equal(t, SandboxReady, result.Status.Phase)
}

func TestSandboxGet_NotFound(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.Get(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSandboxList(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "sb1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.sandboxes["sb2"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "sb2"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestSandboxList_Empty(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.List(context.Background(), "default")

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestSandboxList_WithOptions(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "sb1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.List(context.Background(), "default", ListOptions{Limit: 10, Offset: 0})

	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestSandboxDelete(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["deleteme"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "deleteme"},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "deleteme")

	require.NoError(t, err)
	assert.Empty(t, mock.sandboxes["deleteme"])
}

func TestSandboxDelete_NotFound(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	err := client.Delete(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// --- T030: AttachProvider, DetachProvider, ListProviders tests ---

func TestSandboxAttachProvider(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["my-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "my-sb", ResourceVersion: 2},
		Spec:     &pb.SandboxSpec{Providers: []string{"existing-prov"}},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.AttachProvider(context.Background(), "default", "my-sb", "new-prov", 2)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Attached)
	require.NotNil(t, result.Sandbox)
	assert.Equal(t, "my-sb", result.Sandbox.Name)
}

func TestSandboxAttachProvider_NotFound(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.AttachProvider(context.Background(), "default", "missing", "prov", 1)

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSandboxAttachProvider_Error(t *testing.T) {
	mock := newMockSandboxServer()
	mock.attachErr = status.Error(codes.InvalidArgument, "bad version")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.AttachProvider(context.Background(), "default", "sb", "prov", 99)

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err))
}

func TestSandboxDetachProvider(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["my-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "my-sb", ResourceVersion: 3},
		Spec:     &pb.SandboxSpec{Providers: []string{"prov-a", "prov-b"}},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.DetachProvider(context.Background(), "default", "my-sb", "prov-a", 3)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Detached)
	require.NotNil(t, result.Sandbox)
	assert.Equal(t, "my-sb", result.Sandbox.Name)
}

func TestSandboxDetachProvider_NotFound(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.DetachProvider(context.Background(), "default", "missing", "prov", 1)

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSandboxListProviders(t *testing.T) {
	mock := newMockSandboxServer()
	mock.providers["my-sb"] = []*dm.Provider{
		{Metadata: &dm.ObjectMeta{Name: "claude-prov"}, Type: "claude"},
		{Metadata: &dm.ObjectMeta{Name: "github-prov"}, Type: "github"},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.ListProviders(context.Background(), "default", "my-sb")

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestSandboxListProviders_Empty(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.ListProviders(context.Background(), "default", "empty-sb")

	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestSandboxListProviders_Error(t *testing.T) {
	mock := newMockSandboxServer()
	mock.listProvErr = status.Error(codes.Unavailable, "service down")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.ListProviders(context.Background(), "default", "sb")

	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

// --- T031: WaitReady tests ---

func TestSandboxWaitReady_AlreadyReady(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["ready-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "ready-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.WaitReady(context.Background(), "default", "ready-sb")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ready-sb", result.Name)
	assert.Equal(t, SandboxReady, result.Status.Phase)
}

func TestSandboxWaitReady_BecomesReady(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["pending-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "pending-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	go func() {
		time.Sleep(50 * time.Millisecond)
		mock.setPhase("pending-sb", pb.SandboxPhase_SANDBOX_PHASE_READY)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := client.WaitReady(ctx, "default", "pending-sb", WaitOptions{PollInterval: 20 * time.Millisecond})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, SandboxReady, result.Status.Phase)
}

func TestSandboxWaitReady_ContextTimeout(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["stuck-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "stuck-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.WaitReady(ctx, "default", "stuck-sb", WaitOptions{PollInterval: 20 * time.Millisecond})

	require.Error(t, err)
	assert.True(t, IsDeadlineExceeded(err), "WaitReady must wrap context.DeadlineExceeded in StatusError")
}

func TestSandboxWaitReady_ContextCancelled(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["cancel-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "cancel-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := client.WaitReady(ctx, "default", "cancel-sb", WaitOptions{PollInterval: 20 * time.Millisecond})

	require.Error(t, err)
	assert.True(t, IsCancelled(err), "WaitReady must wrap context.Canceled in StatusError")
}

func TestSandboxWaitReady_SandboxFailed(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["fail-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Name: "fail-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_ERROR},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.WaitReady(context.Background(), "default", "fail-sb")

	require.Error(t, err)
}

func TestSandboxWaitReady_NotFound(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.WaitReady(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

// --- T039: Watch integration tests ---

func TestSandboxWatch_ReceivesEvents(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	ev1 := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev1.Type)
	require.NotNil(t, ev1.Object)
	assert.Equal(t, "sb-1", ev1.Object.Name)
	assert.Equal(t, SandboxProvisioning, ev1.Object.Status.Phase)

	ev2 := <-w.ResultChan()
	assert.Equal(t, EventModified, ev2.Type)
	assert.Equal(t, SandboxReady, ev2.Object.Status.Phase)
}

func TestSandboxWatch_FiltersSandboxEventsOnly(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Log{Log: &pb.SandboxLogLine{Message: "some log"}}},
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
		{Payload: &pb.SandboxStreamEvent_Warning{Warning: &pb.SandboxStreamWarning{Message: "warn"}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	ev := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev.Type)
	assert.Equal(t, "sb-1", ev.Object.Name)

	// Stream ends after server sends all events; channel should close
	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should close after stream ends")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}

func TestSandboxWatch_StopCancelsStream(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)

	<-w.ResultChan()
	w.Stop()

	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should be closed after Stop")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close after Stop")
	}
}

func TestSandboxWatch_RPCError(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["watch-err"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-watch-err", Name: "watch-err"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.watchErr = status.Error(codes.Unavailable, "stream unavailable")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.Watch(context.Background(), "default", "watch-err")

	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

func TestSandboxWatch_MidStreamErrorDeliveredAsStatusError(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
	}
	mock.watchPostEventsErr = status.Error(codes.Unavailable, "connection lost")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	ev1 := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev1.Type)

	ev2 := <-w.ResultChan()
	assert.Equal(t, EventError, ev2.Type)
	require.Error(t, ev2.Err)
	assert.True(t, IsUnavailable(ev2.Err), "mid-stream error should be converted to StatusError")
}

// --- T016: Watch name-to-ID resolution verification tests ---

func TestSandboxWatch_ResolvesNameToID(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["my-sandbox"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "resolved-id-123", Name: "my-sandbox"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchKeepOpen = make(chan struct{})
	defer close(mock.watchKeepOpen)
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "my-sandbox", Id: "resolved-id-123"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "my-sandbox")
	require.NoError(t, err)
	defer w.Stop()

	// Verify the WatchSandboxRequest.Id contains the resolved ID, not the name
	mock.mu.Lock()
	req := mock.watchRequest
	mock.mu.Unlock()
	require.NotNil(t, req)
	assert.Equal(t, "resolved-id-123", req.GetId(), "Watch should send resolved sandbox ID, not the name")
}

func TestSandboxWatch_ResolutionError(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.Watch(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err), "Watch should return NotFound when sandbox name cannot be resolved")
}

func TestSandboxWatch_EmptySandboxName(t *testing.T) {
	mock := newMockSandboxServer()
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.Watch(context.Background(), "default", "")

	require.Error(t, err)
	assert.True(t, IsInvalidArgument(err), "Watch should reject empty sandbox name")
}

// --- T023/T024: StopOnTerminal watch tests ---

func TestSandboxWatch_StopOnTerminal_Ready(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchKeepOpen = make(chan struct{})
	defer close(mock.watchKeepOpen)
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1", WatchOptions{StopOnTerminal: true})
	require.NoError(t, err)
	defer w.Stop()

	// Should receive the Provisioning event
	ev1 := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev1.Type)
	assert.Equal(t, SandboxProvisioning, ev1.Object.Status.Phase)

	// Should receive the Ready event (terminal)
	ev2 := <-w.ResultChan()
	assert.Equal(t, EventModified, ev2.Type)
	assert.Equal(t, SandboxReady, ev2.Object.Status.Phase)

	// Channel should close automatically after terminal event (stream is still open)
	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should close after terminal Ready event")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close after terminal Ready event")
	}
}

func TestSandboxWatch_StopOnTerminal_Error(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchKeepOpen = make(chan struct{})
	defer close(mock.watchKeepOpen)
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_ERROR},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1", WatchOptions{StopOnTerminal: true})
	require.NoError(t, err)
	defer w.Stop()

	// Should receive the Provisioning event
	ev1 := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev1.Type)
	assert.Equal(t, SandboxProvisioning, ev1.Object.Status.Phase)

	// Should receive the Error event (terminal)
	ev2 := <-w.ResultChan()
	assert.Equal(t, EventModified, ev2.Type)
	assert.Equal(t, SandboxError, ev2.Object.Status.Phase)

	// Channel should close automatically after terminal event (stream is still open)
	select {
	case _, ok := <-w.ResultChan():
		assert.False(t, ok, "channel should close after terminal Error event")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close after terminal Error event")
	}
}

func TestSandboxWatch_StopOnTerminal_False_DoesNotClose(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.watchKeepOpen = make(chan struct{})
	defer close(mock.watchKeepOpen)
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	ev := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev.Type)
	assert.Equal(t, SandboxReady, ev.Object.Status.Phase)

	// Channel must NOT close: stream is still open and StopOnTerminal=false
	select {
	case <-w.ResultChan():
		t.Fatal("channel should stay open when StopOnTerminal is false")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSandboxWatch_DeletedEvent(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["sb-1"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "id-1", Name: "sb-1"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
	}
	mock.watchEvents = []*pb.SandboxStreamEvent{
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING},
		}}},
		{Payload: &pb.SandboxStreamEvent_Sandbox{Sandbox: &pb.Sandbox{
			Metadata: &dm.ObjectMeta{Name: "sb-1", Id: "id-1"},
			Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_DELETING},
		}}},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	w, err := client.Watch(context.Background(), "default", "sb-1")
	require.NoError(t, err)
	defer w.Stop()

	ev1 := <-w.ResultChan()
	assert.Equal(t, EventAdded, ev1.Type)

	ev2 := <-w.ResultChan()
	assert.Equal(t, EventDeleted, ev2.Type)
	assert.Equal(t, SandboxDeleting, ev2.Object.Status.Phase)
}

// --- T027: GetLogs tests ---

func TestSandboxGetLogs(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["log-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-id-123", Name: "log-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.getLogsResp = &pb.GetSandboxLogsResponse{
		Logs: []*pb.SandboxLogLine{
			{TimestampMs: 1700000000000, Level: "INFO", Target: "gateway", Message: "connected", Source: "gateway"},
			{TimestampMs: 1700000001000, Level: "DEBUG", Target: "sandbox", Message: "init done", Source: "sandbox"},
		},
		BufferTotal: 42,
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.GetLogs(context.Background(), "default", "log-sb")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Lines, 2)
	assert.Equal(t, uint32(42), result.BufferTotal)
	assert.Equal(t, "INFO", result.Lines[0].Level)
	assert.Equal(t, "connected", result.Lines[0].Message)
	assert.Equal(t, "gateway", result.Lines[0].Source)
	assert.Equal(t, "DEBUG", result.Lines[1].Level)
	assert.Equal(t, "init done", result.Lines[1].Message)

	// Verify name→id resolution: the proto request should contain the sandbox ID
	mock.mu.Lock()
	assert.Equal(t, "sb-id-123", mock.getLogsRequest.GetSandboxId())
	mock.mu.Unlock()
}

func TestSandboxGetLogs_WithOptions(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["opts-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-id-opts", Name: "opts-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.getLogsResp = &pb.GetSandboxLogsResponse{
		Logs:        []*pb.SandboxLogLine{{TimestampMs: 1700000000000, Level: "WARN", Message: "high cpu"}},
		BufferTotal: 100,
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	since := time.Date(2023, 11, 14, 0, 0, 0, 0, time.UTC)
	result, err := client.GetLogs(context.Background(), "default", "opts-sb",
		WithLogLines(50),
		WithLogSince(since),
		WithLogSources("gateway", "sandbox"),
		WithLogMinLevel("WARN"),
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Lines, 1)
	assert.Equal(t, "WARN", result.Lines[0].Level)

	// Verify all options were passed to the proto request
	mock.mu.Lock()
	req := mock.getLogsRequest
	mock.mu.Unlock()
	assert.Equal(t, "sb-id-opts", req.GetSandboxId())
	assert.Equal(t, uint32(50), req.GetLines())
	assert.Equal(t, since.UnixMilli(), req.GetSinceMs())
	assert.Equal(t, []string{"gateway", "sandbox"}, req.GetSources())
	assert.Equal(t, "WARN", req.GetMinLevel())
}

func TestSandboxGetLogs_SandboxNotFound(t *testing.T) {
	mock := newMockSandboxServer()
	// No sandbox registered — Get will return NotFound
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.GetLogs(context.Background(), "default", "nonexistent")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func TestSandboxGetLogs_RPCError(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["rpc-err-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-id-rpc", Name: "rpc-err-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.getLogsErr = status.Error(codes.Unavailable, "log service down")
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	_, err := client.GetLogs(context.Background(), "default", "rpc-err-sb")

	require.Error(t, err)
	assert.True(t, IsUnavailable(err))
}

func TestSandboxGetLogs_EmptyResult(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["empty-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-id-empty", Name: "empty-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	mock.getLogsResp = &pb.GetSandboxLogsResponse{
		BufferTotal: 0,
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	result, err := client.GetLogs(context.Background(), "default", "empty-sb")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Lines)
	assert.Equal(t, uint32(0), result.BufferTotal)
}

func TestSandboxGetLogs_SinceZeroNotSent(t *testing.T) {
	mock := newMockSandboxServer()
	mock.sandboxes["zero-sb"] = &pb.Sandbox{
		Metadata: &dm.ObjectMeta{Id: "sb-id-zero", Name: "zero-sb"},
		Status:   &pb.SandboxStatus{Phase: pb.SandboxPhase_SANDBOX_PHASE_READY},
	}
	client, cleanup := setupSandboxTest(t, mock)
	defer cleanup()

	// Call without WithLogSince — SinceMs should be 0 (not set)
	_, err := client.GetLogs(context.Background(), "default", "zero-sb")

	require.NoError(t, err)
	mock.mu.Lock()
	assert.Equal(t, int64(0), mock.getLogsRequest.GetSinceMs())
	mock.mu.Unlock()
}
