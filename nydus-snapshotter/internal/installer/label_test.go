/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockNodeName = "node-1"

	mockNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes"}}}

	mockLabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes", NodeLabel: nodeLabelValue}}}

	mockMislabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes", NodeLabel: "false"}}}

	mockOtherLabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2", Labels: map[string]string{"kept": "yes", NodeLabel: nodeLabelValue}}}

	mockUnlabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-3", Labels: map[string]string{"kept": "yes"}}}

	mockNodeNotFound = apierrors.NewNotFound(corev1.Resource("nodes"), mockNodeName)

	mockSnapshotterPlugin = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": config.DefaultGRPCAddr}}

	mockFailedPlugin = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": config.DefaultGRPCAddr}, InitErr: status.New(codes.Unknown, "foo").Proto()}

	mockOtherPlugin = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "stargz", Exports: map[string]string{"address": "/run/containerd-stargz-grpc/containerd-stargz-grpc.sock"}}

	mockBuiltinPlugin = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "overlayfs", Exports: map[string]string{"root": "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"}}

	mockAliasedPlugin = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": "/var/run//nydus-snapshotter/nydus-snapshotter.sock"}}
)

type mockContainerd struct {
	introspectionapi.UnimplementedIntrospectionServer
	mu      sync.Mutex
	plugins []*introspectionapi.Plugin
}

func (c *mockContainerd) Plugins(context.Context, *introspectionapi.PluginsRequest) (*introspectionapi.PluginsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &introspectionapi.PluginsResponse{Plugins: c.plugins}, nil
}

func (c *mockContainerd) load(plugins ...*introspectionapi.Plugin) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plugins = plugins
}

type mockHost struct {
	installer   *Installer
	client      *fake.Clientset
	snapshotter *health.Server
	containerd  *mockContainerd
}

func (h *mockHost) labeled(t *testing.T) bool {
	t.Helper()
	return h.labels(t)[NodeLabel] == nodeLabelValue
}

func (h *mockHost) sync(t *testing.T, times int) {
	t.Helper()
	for range times {
		assert.NoError(t, h.installer.syncNodeLabel(t.Context()))
	}
}

func (h *mockHost) verbs() []string {
	verbs := []string{}
	for _, action := range h.client.Actions() {
		verbs = append(verbs, action.GetVerb())
	}

	return verbs
}

func (h *mockHost) labeledNodes(t *testing.T) []string {
	t.Helper()
	nodes, err := h.client.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: NodeLabel})
	assert.NoError(t, err)
	names := []string{}
	for _, node := range nodes.Items {
		names = append(names, node.Name)
	}

	return names
}

func (h *mockHost) fail(verb string, err error, times int) {
	h.client.PrependReactor(verb, "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		if times == 0 {
			return false, nil, nil
		}

		times--
		return true, nil, err
	})
}

func (h *mockHost) labels(t *testing.T) map[string]string {
	t.Helper()
	node, err := h.client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
	assert.NoError(t, err)
	return node.Labels
}

func (h *mockHost) serve(t *testing.T, socket string, register func(server *grpc.Server)) {
	t.Helper()
	socket = hostPath(t, h.installer.cfg, socket)
	assert.NoError(t, os.MkdirAll(filepath.Dir(socket), 0o755))
	listener, err := net.Listen("unix", socket)
	assert.NoError(t, err)
	server := grpc.NewServer()
	register(server)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
}

func newMockHost(t *testing.T, enable bool, nodes ...*corev1.Node) *mockHost {
	t.Helper()
	cfg := newConfig(t)
	cfg.Installer.NodeLabel = config.InstallerNodeLabelConfig{Enable: enable, ContainerdAddr: config.DefaultInstallerContainerdAddr}
	root, err := os.MkdirTemp("", "nydus-") //nolint:usetesting // t.TempDir is too long for the path of a unix socket
	assert.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cfg.Installer.RootfsDir = root

	h := &mockHost{
		installer:   newInstaller(cfg, mocks.NewMockSystemd(gomock.NewController(t))),
		client:      fake.NewClientset(),
		snapshotter: health.NewServer(),
		containerd:  &mockContainerd{plugins: []*introspectionapi.Plugin{mockOtherPlugin, mockSnapshotterPlugin}},
	}
	h.installer.nodeName, h.installer.kubeClient = mockNodeName, h.client
	h.serve(t, config.DefaultGRPCAddr, func(server *grpc.Server) { grpc_health_v1.RegisterHealthServer(server, h.snapshotter) })
	h.serve(t, config.DefaultInstallerContainerdAddr, func(server *grpc.Server) { introspectionapi.RegisterIntrospectionServer(server, h.containerd) })
	for _, node := range nodes {
		_, err := h.client.CoreV1().Nodes().Create(t.Context(), node.DeepCopy(), metav1.CreateOptions{})
		assert.NoError(t, err)
	}
	h.client.ClearActions()

	return h
}

func TestInstaller_initKubeClient(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		prepare func(t *testing.T, h *mockHost)
		expect  func(t *testing.T, h *mockHost, err error)
	}{
		{
			name:    "keep the client it holds",
			host:    "10.96.0.1",
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Same(h.client, h.installer.kubeClient)
			},
		},
		{
			name: "build the client of the api server once",
			host: "10.96.0.1",
			prepare: func(t *testing.T, h *mockHost) {
				writeFiles(t, h.installer.cfg.Installer.TokenDir, map[string]string{"ca.crt": newCertificate(t)})
				h.installer.kubeClient = nil
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				client := h.installer.kubeClient
				assert.NotNil(client)
				assert.NoError(h.installer.initKubeClient())
				assert.Same(client, h.installer.kubeClient)
			},
		},
		{
			name: "pod without an api server",
			prepare: func(t *testing.T, h *mockHost) {
				h.installer.kubeClient = nil
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			h := newMockHost(t, true)
			tc.prepare(t, h)
			tc.expect(t, h, h.installer.initKubeClient())
		})
	}
}

func TestInstaller_syncNodeLabel(t *testing.T) {
	tests := []struct {
		name    string
		enable  bool
		nodes   []*corev1.Node
		prepare func(t *testing.T, h *mockHost)
		expect  func(t *testing.T, h *mockHost, err error)
	}{
		{
			name:    "label the node while the snapshotter serves and containerd has loaded it",
			enable:  true,
			nodes:   []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, h.labels(t))
			},
		},
		{
			name:    "read a node that is right without patching it",
			enable:  true,
			nodes:   []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, h.verbs())
			},
		},
		{
			name:   "keep the label on a check that fails, without reading the node",
			enable: true,
			nodes:  []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load()
				h.sync(t, notReadyThreshold-2)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(h.verbs())
				assert.True(h.labeled(t))
				assert.Equal("containerd has loaded no proxy snapshotter at "+config.DefaultGRPCAddr, h.installer.notReady)
			},
		},
		{
			name:   "keep the label on checks cut short because the installer stops",
			enable: true,
			nodes:  []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				for range notReadyThreshold {
					assert.NoError(t, h.installer.syncNodeLabel(ctx))
				}
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, h.verbs())
				assert.True(h.labeled(t))
				assert.Zero(h.installer.notReadyChecks)
			},
		},
		{
			name:   "count the failed checks in a row only",
			enable: true,
			nodes:  []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load()
				h.sync(t, notReadyThreshold-1)
				h.containerd.load(mockSnapshotterPlugin)
				h.sync(t, 1)
				h.containerd.load()
				h.sync(t, notReadyThreshold-2)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(h.labeled(t))
			},
		},
		{
			name:   "read a node without the label without patching it while not ready",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load()
				h.sync(t, notReadyThreshold-1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, h.verbs())
			},
		},
		{
			name:   "put back a label removed behind the installer",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				assert.NoError(t, h.installer.syncNodeLabel(t.Context()))
				_, err := h.client.CoreV1().Nodes().Update(t.Context(), mockNode.DeepCopy(), metav1.UpdateOptions{})
				assert.NoError(t, err)
				assert.False(t, h.labeled(t))
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, h.labels(t))
			},
		},
		{
			name:    "set a label of another value",
			enable:  true,
			nodes:   []*corev1.Node{mockMislabeledNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, h.labels(t))
			},
		},
		{
			name:   "remove a label of another value while not ready",
			enable: true,
			nodes:  []*corev1.Node{mockMislabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load()
				h.sync(t, notReadyThreshold-1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockNode.Labels, h.labels(t))
			},
		},
		{
			name:    "leave the nodes alone unless the node is labeled",
			nodes:   []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(h.client.Actions())
			},
		},
		{
			name:   "remove the label once the snapshotter is not serving for checks in a row",
			enable: true,
			nodes:  []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.snapshotter.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
				h.sync(t, notReadyThreshold-1)
				assert.True(t, h.labeled(t))
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockNode.Labels, h.labels(t))
				assert.Equal("snapshotter is NOT_SERVING", h.installer.notReady)
			},
		},
		{
			name:   "remove the label once containerd has not loaded the snapshotter for checks in a row",
			enable: true,
			nodes:  []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load(mockOtherPlugin)
				h.sync(t, notReadyThreshold-1)
				assert.True(t, h.labeled(t))
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockNode.Labels, h.labels(t))
			},
		},
		{
			name:   "label the node again once containerd loads the snapshotter",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load()
				h.sync(t, notReadyThreshold)
				assert.False(t, h.labeled(t))
				h.containerd.load(mockSnapshotterPlugin)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(h.labeled(t))
				assert.Empty(h.installer.notReady)
				assert.Zero(h.installer.notReadyChecks)
			},
		},
		{
			name:   "report a setup that fails and try it again on the next sync",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				t.Setenv("KUBERNETES_SERVICE_HOST", "")
				h.installer.kubeClient = nil
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				h.installer.kubeClient = h.client
				assert.NoError(h.installer.syncNodeLabel(t.Context()))
				assert.True(h.labeled(t))
			},
		},
		{
			name:    "node that is missing",
			enable:  true,
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "get node "+mockNodeName)
			},
		},
		{
			name:   "node that cannot be read",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.fail("get", errors.New("foo"), 1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "get node "+mockNodeName+": foo")
				assert.Equal([]string{"get"}, h.verbs())
			},
		},
		{
			name:   "node that cannot be patched",
			enable: true,
			nodes:  []*corev1.Node{mockNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.fail("patch", errors.New("foo"), 1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "patch node "+mockNodeName+": foo")
				assert.NoError(h.installer.syncNodeLabel(t.Context()))
				assert.True(h.labeled(t))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newMockHost(t, tc.enable, tc.nodes...)
			tc.prepare(t, h)
			h.client.ClearActions()
			tc.expect(t, h, h.installer.syncNodeLabel(t.Context()))
		})
	}
}

func TestInstaller_ready(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *mockHost)
		expect  func(t *testing.T, err error)
	}{
		{
			name:    "snapshotter that serves and that containerd has loaded",
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "snapshotter that is not serving",
			prepare: func(t *testing.T, h *mockHost) {
				h.snapshotter.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "snapshotter is NOT_SERVING")
			},
		},
		{
			name: "snapshotter that does not answer",
			prepare: func(t *testing.T, h *mockHost) {
				assert.NoError(t, os.Remove(hostPath(t, h.installer.cfg, config.DefaultGRPCAddr)))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "check snapshotter health")
			},
		},
		{
			name: "snapshotter that does not serve at the socket of the config",
			prepare: func(t *testing.T, h *mockHost) {
				h.installer.cfg.GRPC.Addr = "/run/nydus-snapshotter/other.sock"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "check snapshotter health")
			},
		},
		{
			name: "snapshotter that containerd has loaded at another spelling of its socket",
			prepare: func(t *testing.T, h *mockHost) {
				assert.NoError(t, os.MkdirAll(filepath.Join(h.installer.cfg.Installer.RootfsDir, "var"), 0o755))
				assert.NoError(t, os.Symlink("/run", filepath.Join(h.installer.cfg.Installer.RootfsDir, "var/run")))
				h.containerd.load(mockBuiltinPlugin, mockAliasedPlugin)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "containerd that has loaded no snapshotter at the socket",
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load(mockOtherPlugin)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "containerd has loaded no proxy snapshotter at "+config.DefaultGRPCAddr)
			},
		},
		{
			name: "containerd that failed to load the snapshotter",
			prepare: func(t *testing.T, h *mockHost) {
				h.containerd.load(mockFailedPlugin)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "containerd failed to load snapshotter nydus: foo")
			},
		},
		{
			name: "containerd that does not answer",
			prepare: func(t *testing.T, h *mockHost) {
				assert.NoError(t, os.Remove(hostPath(t, h.installer.cfg, config.DefaultInstallerContainerdAddr)))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "list containerd snapshotters")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newMockHost(t, true)
			tc.prepare(t, h)
			tc.expect(t, h.installer.ready(t.Context()))
		})
	}
}

func TestInstaller_UnlabelNodes(t *testing.T) {
	tests := []struct {
		name    string
		nodes   []*corev1.Node
		prepare func(t *testing.T, h *mockHost)
		expect  func(t *testing.T, h *mockHost, err error)
	}{
		{
			name:    "remove the label from every node that carries it",
			nodes:   []*corev1.Node{mockLabeledNode, mockOtherLabeledNode, mockUnlabeledNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, h.verbs())
				assert.Empty(h.labeledNodes(t))
				assert.Equal(mockNode.Labels, h.labels(t))
			},
		},
		{
			name:    "leave a cluster without the label alone",
			nodes:   []*corev1.Node{mockNode, mockUnlabeledNode},
			prepare: func(t *testing.T, h *mockHost) {},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list"}, h.verbs())
			},
		},
		{
			name:  "go on to the next node when a patch fails",
			nodes: []*corev1.Node{mockLabeledNode, mockOtherLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.fail("patch", errors.New("foo"), 1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "patch node ")
				assert.ErrorContains(err, ": foo")
				assert.Equal([]string{"list", "patch", "patch"}, h.verbs())
				assert.Len(h.labeledNodes(t), 1)
			},
		},
		{
			name:  "skip a node deleted since it was listed",
			nodes: []*corev1.Node{mockLabeledNode, mockOtherLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.fail("patch", mockNodeNotFound, 1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, h.verbs())
			},
		},
		{
			name:  "nodes that cannot be listed",
			nodes: []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.fail("list", errors.New("foo"), 1)
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "list labeled nodes: foo")
				assert.Equal([]string{"list"}, h.verbs())
			},
		},
		{
			name:  "pod without an api server",
			nodes: []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, h *mockHost) {
				h.installer.kubeClient = nil
			},
			expect: func(t *testing.T, h *mockHost, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(h.verbs())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			h := newMockHost(t, false, tc.nodes...)
			tc.prepare(t, h)
			tc.expect(t, h, h.installer.UnlabelNodes(t.Context()))
		})
	}
}

func TestInstaller_waitServing(t *testing.T) {
	tests := []struct {
		name   string
		enable bool
		status grpc_health_v1.HealthCheckResponse_ServingStatus
		expect func(t *testing.T, waited time.Duration)
	}{
		{
			name:   "return once the snapshotter serves",
			enable: true,
			status: grpc_health_v1.HealthCheckResponse_SERVING,
			expect: func(t *testing.T, waited time.Duration) {
				assert := assert.New(t)
				assert.Less(waited, servingInterval)
			},
		},
		{
			name:   "return at once unless the node is labeled",
			status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			expect: func(t *testing.T, waited time.Duration) {
				assert := assert.New(t)
				assert.Less(waited, 100*time.Millisecond)
			},
		},
		{
			name:   "give up when the context is done",
			enable: true,
			status: grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			expect: func(t *testing.T, waited time.Duration) {
				assert := assert.New(t)
				assert.GreaterOrEqual(waited, 100*time.Millisecond)
				assert.Less(waited, servingTimeout)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newMockHost(t, tc.enable)
			h.snapshotter.SetServingStatus("", tc.status)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()

			start := time.Now()
			h.installer.waitServing(ctx)
			tc.expect(t, time.Since(start))
		})
	}
}

func newCertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestInstaller_newKubeClient(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		ca     string
		expect func(t *testing.T, client kubernetes.Interface, err error)
	}{
		{
			name: "client of the pod's api server",
			host: "10.96.0.1",
			ca:   newCertificate(t),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotNil(client)
			},
		},
		{
			name: "ca that is no certificate",
			host: "10.96.0.1",
			ca:   mockCA,
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unable to load root certificates")
			},
		},
		{
			name: "pod without an api server",
			ca:   mockCA,
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Nil(client)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := newConfig(t)
			writeFiles(t, cfg.Installer.TokenDir, map[string]string{"ca.crt": tc.ca})
			client, err := newInstaller(cfg, mocks.NewMockSystemd(gomock.NewController(t))).newKubeClient()
			tc.expect(t, client, err)
		})
	}
}

func TestInstaller_Run_nodeLabel(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, h *mockHost, cancel context.CancelFunc, done <-chan error)
	}{
		{
			name: "label the node once installed and keep the label on stop",
			expect: func(t *testing.T, h *mockHost, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
				assert.Equal(mockLabeledNode.Labels, h.labels(t))
			},
		},
		{
			name: "follow what containerd has loaded",
			expect: func(t *testing.T, h *mockHost, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				h.containerd.load()
				assert.Eventually(func() bool { return !h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				h.containerd.load(mockSnapshotterPlugin)
				assert.Eventually(func() bool { return h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
				assert.Equal(mockLabeledNode.Labels, h.labels(t))
			},
		},
		{
			name: "put back a label removed behind the installer",
			expect: func(t *testing.T, h *mockHost, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool { return h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				_, err := h.client.CoreV1().Nodes().Update(t.Context(), mockNode.DeepCopy(), metav1.UpdateOptions{})
				assert.NoError(err)
				assert.Eventually(func() bool { return h.labeled(t) }, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newMockHost(t, true, mockNode)
			h.installer.cfg.Installer.SyncInterval = config.Duration(10 * time.Millisecond)
			mockSystemd := h.installer.systemd.(*mocks.MockSystemd).EXPECT()
			mockSystemd.Ping(gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.EnableUnitFiles(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.RestartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.StartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.installer.Run(ctx) }()
			tc.expect(t, h, cancel, done)
		})
	}
}
