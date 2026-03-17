package committer

import (
	"context"
	"errors"
	"testing"

	containerdclient "github.com/containerd/containerd/v2/client"
	corecontainers "github.com/containerd/containerd/v2/core/containers"
	"github.com/stretchr/testify/require"
)

type mockContainerStore struct {
	containers []corecontainers.Container
	err        error
}

func (m *mockContainerStore) Get(context.Context, string) (corecontainers.Container, error) {
	return corecontainers.Container{}, nil
}

func (m *mockContainerStore) List(context.Context, ...string) ([]corecontainers.Container, error) {
	return m.containers, m.err
}

func (m *mockContainerStore) Create(context.Context, corecontainers.Container) (corecontainers.Container, error) {
	return corecontainers.Container{}, nil
}

func (m *mockContainerStore) Update(context.Context, corecontainers.Container, ...string) (corecontainers.Container, error) {
	return corecontainers.Container{}, nil
}

func (m *mockContainerStore) Delete(context.Context, string) error {
	return nil
}

func newWalkerClient(t *testing.T, store *mockContainerStore) *containerdclient.Client {
	t.Helper()

	client, err := containerdclient.New("", containerdclient.WithServices(containerdclient.WithContainerStore(store)))
	require.NoError(t, err)

	return client
}

func TestWalkK8sPrefixRejection(t *testing.T) {
	walker := NewContainerWalker(nil, nil)
	count, err := walker.Walk(context.Background(), "k8s://foo")
	require.Equal(t, -1, count)
	require.ErrorContains(t, err, "not supported")
}

func TestWalkContainersQueryFails(t *testing.T) {
	client := newWalkerClient(t, &mockContainerStore{err: errors.New("query failed")})

	walker := NewContainerWalker(client, func(context.Context, Found) error { return nil })
	count, err := walker.Walk(context.Background(), "abc")
	require.Equal(t, -1, count)
	require.EqualError(t, err, "query failed")
}

func TestWalkOnFoundCallbackFails(t *testing.T) {
	client := newWalkerClient(t, &mockContainerStore{containers: []corecontainers.Container{{ID: "abc"}}})

	walker := NewContainerWalker(client, func(context.Context, Found) error { return errors.New("callback failed") })
	count, err := walker.Walk(context.Background(), "abc")
	require.Equal(t, -1, count)
	require.EqualError(t, err, "callback failed")
}

func TestWalkSuccessfulPath(t *testing.T) {
	client := newWalkerClient(t, &mockContainerStore{containers: []corecontainers.Container{{ID: "abc"}, {ID: "abcd"}}})

	seen := 0
	walker := NewContainerWalker(client, func(_ context.Context, found Found) error {
		seen++
		require.Equal(t, 2, found.MatchCount)
		require.Equal(t, "abc", found.Req)
		require.Equal(t, seen-1, found.MatchIndex)
		return nil
	})
	count, err := walker.Walk(context.Background(), "abc")
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, 2, seen)
}
