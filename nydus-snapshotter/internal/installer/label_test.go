/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockNodeName                        = "node-1"
	mockNode                            = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes"}}}
	mockLabeledNode                     = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes", NodeLabel: nodeLabelValue}}}
	mockMislabeledNode                  = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes", NodeLabel: "false"}}}
	mockNydusSnapshotterPlugin          = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": config.DefaultGRPCAddr}}
	mockFailedPlugin                    = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": config.DefaultGRPCAddr}, InitErr: status.New(codes.Unknown, "foo").Proto()}
	mockOtherPlugin                     = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "stargz", Exports: map[string]string{"address": "/run/containerd-stargz-grpc/containerd-stargz-grpc.sock"}}
	mockBuiltinPlugin                   = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "overlayfs", Exports: map[string]string{"root": "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"}}
	mockAliasedPlugin                   = &introspectionapi.Plugin{Type: snapshotterPluginType, ID: "nydus", Exports: map[string]string{"address": "/var/run//nydus-snapshotter/nydus-snapshotter.sock"}}
	mockPluginsResponse                 = &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{mockOtherPlugin, mockNydusSnapshotterPlugin}}
	mockNoPluginsResponse               = &introspectionapi.PluginsResponse{}
	mockOtherPluginsResponse            = &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{mockOtherPlugin}}
	mockNydusSnapshotterPluginsResponse = &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{mockNydusSnapshotterPlugin}}
	mockFailedPluginsResponse           = &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{mockFailedPlugin}}
	mockAliasedPluginsResponse          = &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{mockBuiltinPlugin, mockAliasedPlugin}}
)

type mockContainerd struct {
	introspectionapi.UnimplementedIntrospectionServer
	plugins atomic.Pointer[introspectionapi.PluginsResponse]
}

func (c *mockContainerd) Plugins(context.Context, *introspectionapi.PluginsRequest) (*introspectionapi.PluginsResponse, error) {
	return c.plugins.Load(), nil
}

func TestInstaller_syncNodeLabel(t *testing.T) {
	tests := []struct {
		name   string
		nodes  []runtime.Object
		mock   func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd)
		expect func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error)
	}{
		{
			name:  "label the node while the snapshotter serves and containerd has loaded it",
			nodes: []runtime.Object{mockNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, node.Labels)
			},
		},
		{
			name:  "read a node that is right without patching it",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, verbs)
			},
		},
		{
			name:  "keep the label on a check cut short because the installer stops",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				assert.NoError(t, i.syncNodeLabel(ctx))
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, verbs)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(nodeLabelValue, node.Labels[NodeLabel])
			},
		},
		{
			name:  "read a node without the label without patching it while not ready",
			nodes: []runtime.Object{mockNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockNoPluginsResponse)
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"get"}, verbs)
			},
		},
		{
			name:  "put back a label removed behind the installer",
			nodes: []runtime.Object{mockNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				assert.NoError(t, i.syncNodeLabel(t.Context()))
				node, err := client.CoreV1().Nodes().Update(t.Context(), mockNode.DeepCopy(), metav1.UpdateOptions{})
				assert.NoError(t, err)
				assert.NotEqual(t, nodeLabelValue, node.Labels[NodeLabel])
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, node.Labels)
			},
		},
		{
			name:  "set a label of another value",
			nodes: []runtime.Object{mockMislabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, node.Labels)
			},
		},
		{
			name:  "remove a label of another value while not ready",
			nodes: []runtime.Object{mockMislabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockNoPluginsResponse)
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockNode.Labels, node.Labels)
			},
		},
		{
			name:  "remove the label once the snapshotter is not serving",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				snapshotter.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockNode.Labels, node.Labels)
			},
		},
		{
			name:  "remove the label once containerd has not loaded the snapshotter",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockOtherPluginsResponse)
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockNode.Labels, node.Labels)
			},
		},
		{
			name:  "label the node again once containerd loads the snapshotter",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockNoPluginsResponse)
				assert.NoError(t, i.syncNodeLabel(t.Context()))
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.NotEqual(t, nodeLabelValue, node.Labels[NodeLabel])
				containerd.plugins.Store(mockNydusSnapshotterPluginsResponse)
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(nodeLabelValue, node.Labels[NodeLabel])
			},
		},
		{
			name: "node that is missing",
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "get node "+mockNodeName)
			},
		},
		{
			name:  "node that cannot be read",
			nodes: []runtime.Object{mockNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				client.PrependReactor("get", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("foo")
				})
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "get node "+mockNodeName+": foo")
				assert.Equal([]string{"get"}, verbs)
			},
		},
		{
			name:  "node that cannot be patched",
			nodes: []runtime.Object{mockNode},
			mock: func(t *testing.T, i *Installer, client *fake.Clientset, snapshotter *health.Server, containerd *mockContainerd) {
				failed := false
				client.PrependReactor("patch", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}

					failed = true
					return true, nil, errors.New("foo")
				})
			},
			expect: func(t *testing.T, i *Installer, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "patch node "+mockNodeName+": foo")
				assert.NoError(i.syncNodeLabel(t.Context()))
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(nodeLabelValue, node.Labels[NodeLabel])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			snapshotter := health.NewServer()
			containerd := &mockContainerd{}
			containerd.plugins.Store(mockPluginsResponse)
			for socket, register := range map[string]func(server *grpc.Server){
				config.DefaultGRPCAddr:       func(server *grpc.Server) { grpc_health_v1.RegisterHealthServer(server, snapshotter) },
				config.DefaultContainerdAddr: func(server *grpc.Server) { introspectionapi.RegisterIntrospectionServer(server, containerd) },
			} {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, filepath.Dir(socket)), 0o755))
				listener, err := net.Listen("unix", filepath.Join(hostRootMount, socket))
				if err != nil {
					t.Fatal(err)
				}

				server := grpc.NewServer()
				register(server)
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(server.Stop)
			}

			client := fake.NewClientset(tc.nodes...)
			i, err := New(config.New(), config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			i.nodeName, i.kubeClient = mockNodeName, client
			tc.mock(t, i, client, snapshotter, containerd)
			client.ClearActions()

			err = i.syncNodeLabel(t.Context())
			var verbs []string
			for _, action := range client.Actions() {
				verbs = append(verbs, action.GetVerb())
			}

			tc.expect(t, i, client, verbs, err)
		})
	}
}

func TestInstaller_checkNydusSnapshotterReady(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd)
		expect func(t *testing.T, err error)
	}{
		{
			name: "snapshotter that serves and that containerd has loaded",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "snapshotter that is not serving",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				snapshotter.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "snapshotter is NOT_SERVING")
			},
		},
		{
			name: "snapshotter that does not answer",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				assert.NoError(t, os.Remove(filepath.Join(hostRootMount, config.DefaultGRPCAddr)))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "check snapshotter health")
			},
		},
		{
			name: "snapshotter that does not serve at the socket of the config",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				cfg.GRPC.Addr = "/run/nydus-snapshotter/other.sock"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "check snapshotter health")
			},
		},
		{
			name: "snapshotter that containerd has loaded at another spelling of its socket",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, "var"), 0o755))
				assert.NoError(t, os.Symlink("/run", filepath.Join(hostRootMount, "var/run")))
				containerd.plugins.Store(mockAliasedPluginsResponse)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "containerd that has loaded no snapshotter at the socket",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockOtherPluginsResponse)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "containerd has loaded no proxy snapshotter at "+config.DefaultGRPCAddr)
			},
		},
		{
			name: "containerd that failed to load the snapshotter",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				containerd.plugins.Store(mockFailedPluginsResponse)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "containerd failed to load snapshotter nydus: foo")
			},
		},
		{
			name: "containerd that does not answer",
			mock: func(t *testing.T, cfg *config.Config, snapshotter *health.Server, containerd *mockContainerd) {
				assert.NoError(t, os.Remove(filepath.Join(hostRootMount, config.DefaultContainerdAddr)))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "list containerd snapshotters")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			snapshotter := health.NewServer()
			containerd := &mockContainerd{}
			containerd.plugins.Store(mockPluginsResponse)
			for socket, register := range map[string]func(server *grpc.Server){
				config.DefaultGRPCAddr:       func(server *grpc.Server) { grpc_health_v1.RegisterHealthServer(server, snapshotter) },
				config.DefaultContainerdAddr: func(server *grpc.Server) { introspectionapi.RegisterIntrospectionServer(server, containerd) },
			} {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, filepath.Dir(socket)), 0o755))
				listener, err := net.Listen("unix", filepath.Join(hostRootMount, socket))
				if err != nil {
					t.Fatal(err)
				}

				server := grpc.NewServer()
				register(server)
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(server.Stop)
			}

			cfg := config.New()
			tc.mock(t, cfg, snapshotter, containerd)

			i, err := New(cfg, config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, i.checkNydusSnapshotterReady(t.Context()))
		})
	}
}

func TestInstaller_waitForNydusSnapshotter(t *testing.T) {
	tests := []struct {
		name   string
		status grpc_health_v1.HealthCheckResponse_ServingStatus
		expect func(t *testing.T, waited time.Duration)
	}{
		{
			name:   "return once the snapshotter serves",
			status: grpc_health_v1.HealthCheckResponse_SERVING,
			expect: func(t *testing.T, waited time.Duration) {
				assert := assert.New(t)
				assert.Less(waited, servingInterval)
			},
		},
		{
			name:   "give up when the context is done",
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
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, filepath.Dir(config.DefaultGRPCAddr)), 0o755))
			listener, err := net.Listen("unix", filepath.Join(hostRootMount, config.DefaultGRPCAddr))
			if err != nil {
				t.Fatal(err)
			}

			snapshotter := health.NewServer()
			snapshotter.SetServingStatus("", tc.status)
			server := grpc.NewServer()
			grpc_health_v1.RegisterHealthServer(server, snapshotter)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)

			i, err := New(config.New(), config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()

			start := time.Now()
			i.waitForNydusSnapshotter(ctx)
			tc.expect(t, time.Since(start))
		})
	}
}

func TestInstaller_Run_nodeLabel(t *testing.T) {
	tests := []struct {
		name      string
		nodeLabel bool
		expect    func(t *testing.T, client *fake.Clientset, containerd *mockContainerd, cancel context.CancelFunc, done <-chan error)
	}{
		{
			name: "leave the nodes alone without node label",
			expect: func(t *testing.T, client *fake.Clientset, containerd *mockContainerd, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool {
					_, err := os.Stat(filepath.Join(hostRootMount, nydusSnapshotterBinary))
					return err == nil
				}, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
				assert.Empty(client.Actions())
			},
		},
		{
			name:      "label the node once installed and keep the label on stop",
			nodeLabel: true,
			expect: func(t *testing.T, client *fake.Clientset, containerd *mockContainerd, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] == nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, node.Labels)
			},
		},
		{
			name:      "follow what containerd has loaded",
			nodeLabel: true,
			expect: func(t *testing.T, client *fake.Clientset, containerd *mockContainerd, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] == nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				containerd.plugins.Store(mockNoPluginsResponse)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] != nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				containerd.plugins.Store(mockNydusSnapshotterPluginsResponse)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] == nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(mockLabeledNode.Labels, node.Labels)
			},
		},
		{
			name:      "put back a label removed behind the installer",
			nodeLabel: true,
			expect: func(t *testing.T, client *fake.Clientset, containerd *mockContainerd, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] == nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				_, err := client.CoreV1().Nodes().Update(t.Context(), mockNode.DeepCopy(), metav1.UpdateOptions{})
				assert.NoError(err)
				assert.Eventually(func() bool {
					node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
					return err == nil && node.Labels[NodeLabel] == nodeLabelValue
				}, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			for _, path := range mockResetPaths {
				assert.NoError(t, os.RemoveAll(path))
			}

			assert.NoError(t, os.CopyFS("/", mockImage))
			assert.NoError(t, os.CopyFS(unitDir, os.DirFS("../../deploy/systemd")))
			assert.NoError(t, os.CopyFS(filepath.Dir(config.DefaultPath), os.DirFS("../../deploy/nydus-snapshotter")))
			snapshotter := health.NewServer()
			containerd := &mockContainerd{}
			containerd.plugins.Store(mockPluginsResponse)
			for socket, register := range map[string]func(server *grpc.Server){
				config.DefaultGRPCAddr:       func(server *grpc.Server) { grpc_health_v1.RegisterHealthServer(server, snapshotter) },
				config.DefaultContainerdAddr: func(server *grpc.Server) { introspectionapi.RegisterIntrospectionServer(server, containerd) },
			} {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, filepath.Dir(socket)), 0o755))
				listener, err := net.Listen("unix", filepath.Join(hostRootMount, socket))
				if err != nil {
					t.Fatal(err)
				}

				server := grpc.NewServer()
				register(server)
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(server.Stop)
			}

			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := mocks.NewMockSystemd(ctl)
			mockSystemd.EXPECT().Ping(gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.EXPECT().EnableUnitFiles(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.EXPECT().RestartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockSystemd.EXPECT().StartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			client := fake.NewClientset(mockNode)
			cfg := config.New()
			cfg.Installer.SyncInterval = config.Duration(10 * time.Millisecond)
			cfg.Installer.Registries.Enable = true
			i, err := New(cfg, config.DefaultPath, mockSystemd)
			if err != nil {
				t.Fatal(err)
			}

			cfg.Installer.NodeLabel.Enable = tc.nodeLabel
			i.nodeName, i.kubeClient = mockNodeName, client

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- i.Run(ctx) }()
			tc.expect(t, client, containerd, cancel, done)
		})
	}
}
