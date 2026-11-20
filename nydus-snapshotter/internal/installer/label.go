/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	"github.com/containerd/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/pager"
)

const (
	// NodeLabel is the label of a node whose Pods can use the snapshotter,
	// for Pods and RuntimeClasses to select, as kata-deploy labels a node
	// once its runtime is installed, refer to
	// https://github.com/kata-containers/kata-containers/blob/3.2.0/tools/packaging/kata-deploy/scripts/kata-deploy.sh.
	NodeLabel = "d7y.io/nydus-snapshotter"

	// nodeLabelValue is the value of NodeLabel.
	nodeLabelValue = "true"

	// labelPatch sets NodeLabel, refer to
	// https://datatracker.ietf.org/doc/html/rfc7386.
	labelPatch = `{"metadata":{"labels":{"` + NodeLabel + `":"` + nodeLabelValue + `"}}}`

	// unlabelPatch removes NodeLabel, which a node without it accepts.
	unlabelPatch = `{"metadata":{"labels":{"` + NodeLabel + `":null}}}`

	// snapshotterPluginType is the type containerd gives its snapshotters,
	// proxy plugins included, refer to
	// https://github.com/containerd/containerd/blob/main/plugins/types.go.
	snapshotterPluginType = "io.containerd.snapshotter.v1"

	// servingTimeout is how long the install waits for the snapshotter it
	// started to serve, before a later sync labels the node instead.
	servingTimeout = 30 * time.Second

	// servingInterval is how often that wait checks the snapshotter.
	servingInterval = time.Second

	// requestTimeout bounds a call to the snapshotter, containerd and the
	// API server.
	requestTimeout = 10 * time.Second

	// notReadyThreshold is how many checks in a row have to fail before the
	// label is removed, the default failureThreshold of a probe, refer to
	// https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#Probe.
	notReadyThreshold = 3

	// kubeQPS is the rate of the requests to the API server, kubelet's
	// default, so UnlabelNodes clears 5000 nodes within the five minutes
	// helm gives a hook, refer to
	// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/kubelet/apis/config/v1beta1/defaults.go.
	kubeQPS = 50

	// kubeBurst is the burst of those requests, kubelet's default.
	kubeBurst = 100
)

// prepareNodeLabel reads, once, what labeling the node takes: the socket of
// the snapshotter from the config installed on the host, and a client of the
// API server. A failure is the caller's to report and is tried again on the
// next sync, so it never stops the config and credential sync.
func (i *Installer) prepareNodeLabel() error {
	if i.snapshotterAddr == "" {
		cfg, err := i.cfg.installed()
		if err != nil {
			return err
		}

		i.snapshotterAddr = cfg.GRPC.Addr
	}

	return i.initKubeClient()
}

// syncNodeLabel makes NodeLabel follow whether Pods on the node can use the
// snapshotter, and patches the node only when its label differs, so a label
// changed behind the installer is put right. The label is kept through a
// check that fails once and when the installer stops: the DaemonSet
// controller deletes the Pods of a DaemonSet that selects the label from a
// node that loses it.
//
//	snapshotter SERVING ──┐
//	                      ├─▶ both ───────────────────▶ d7y.io/nydus-snapshotter=true
//	containerd loaded it ─┘   else, 3 checks in a row ─▶ label removed
func (i *Installer) syncNodeLabel(ctx context.Context) error {
	if !i.cfg.NodeLabel.Enable {
		return nil
	}

	if err := i.prepareNodeLabel(); err != nil {
		return err
	}

	logger := log.G(ctx).WithFields(log.Fields{"node": i.cfg.NodeName, "label": NodeLabel})
	notReady := ""
	if err := i.ready(ctx); err != nil {
		notReady = err.Error()
	}

	// Say why the node has no label when the reason changes, not on every
	// sync.
	if notReady != "" && notReady != i.notReady {
		logger.WithField("reason", notReady).Warn("node is not ready for the label")
	}

	i.notReady = notReady
	ready := notReady == ""
	if ready {
		i.notReadyChecks = 0
	} else {
		i.notReadyChecks++
	}

	if !ready && i.notReadyChecks < notReadyThreshold {
		return nil
	}

	value, labeled, err := i.nodeLabel(ctx)
	if err != nil {
		return err
	}

	// A label of another value is not the installer's, and is put right too.
	if ready && value == nodeLabelValue || !ready && !labeled {
		return nil
	}

	patch, message := labelPatch, "labeled node"
	if !ready {
		patch, message = unlabelPatch, "removed node label"
	}

	if err := i.patchNode(ctx, i.cfg.NodeName, patch); err != nil {
		return err
	}

	logger.Info(message)
	return nil
}

// UnlabelNodes removes NodeLabel from every node that carries it. It is the
// post-delete hook of the chart: an installer that stops keeps its label, so
// the uninstall removes them, as node-feature-discovery prunes its labels
// with such a hook, refer to
// https://github.com/kubernetes-sigs/node-feature-discovery/blob/master/deployment/helm/node-feature-discovery/templates/post-delete-job.yaml.
//
//	installer stops ─▶ label kept, the next installer Pod takes it over
//	helm uninstall ──▶ post-delete hook ─▶ UnlabelNodes ─▶ label removed
func (i *Installer) UnlabelNodes(ctx context.Context) error {
	if err := i.initKubeClient(); err != nil {
		return err
	}

	// List in pages, so the labeled nodes of a large cluster are never held
	// at once.
	nodes := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return i.kubeClient.CoreV1().Nodes().List(ctx, opts)
	})

	var errs []error
	if err := nodes.EachListItem(ctx, metav1.ListOptions{LabelSelector: NodeLabel}, func(obj runtime.Object) error {
		node, err := meta.Accessor(obj)
		if err != nil {
			return err
		}

		// A node deleted since it was listed has no label left to remove.
		switch err := i.patchNode(ctx, node.GetName(), unlabelPatch); {
		case apierrors.IsNotFound(err):
		case err != nil:
			errs = append(errs, err)
		default:
			log.G(ctx).WithFields(log.Fields{"node": node.GetName(), "label": NodeLabel}).Info("removed node label")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("list labeled nodes: %w", err)
	}

	return errors.Join(errs...)
}

// nodeLabel returns the value of NodeLabel on the node and whether the node
// carries it. A read at resource version 0 is answered from the cache of the
// API server, refer to
// https://kubernetes.io/docs/reference/using-api/api-concepts/#semantics-for-get-and-list;
// a stale answer costs one patch that changes nothing.
func (i *Installer) nodeLabel(ctx context.Context) (string, bool, error) {
	node, err := i.kubeClient.CoreV1().Nodes().Get(ctx, i.cfg.NodeName, metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return "", false, fmt.Errorf("get node %s: %w", i.cfg.NodeName, err)
	}

	value, labeled := node.Labels[NodeLabel]
	return value, labeled, nil
}

// patchNode applies a merge patch to a node.
func (i *Installer) patchNode(ctx context.Context, name, patch string) error {
	if _, err := i.kubeClient.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch node %s: %w", name, err)
	}

	return nil
}

// waitServing waits for the snapshotter to serve, so the node is labeled
// right after the install and not a sync later.
func (i *Installer) waitServing(ctx context.Context) {
	if !i.cfg.NodeLabel.Enable || i.prepareNodeLabel() != nil {
		return
	}

	// The poll fails only when the wait is over; ready reports why.
	_ = wait.PollUntilContextTimeout(ctx, servingInterval, servingTimeout, true, func(ctx context.Context) (bool, error) {
		return i.serving(ctx) == nil, nil
	})
}

// ready returns nil when Pods on the node can use the snapshotter: it
// serves, and the running containerd has loaded it.
func (i *Installer) ready(ctx context.Context) error {
	if err := i.serving(ctx); err != nil {
		return err
	}

	return i.loaded(ctx)
}

// serving returns nil when the snapshotter on the host answers its gRPC
// health check with SERVING.
func (i *Installer) serving(ctx context.Context) error {
	conn, err := i.dial(i.snapshotterAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return fmt.Errorf("check snapshotter health: %w", err)
	}

	if status := resp.GetStatus(); status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("snapshotter is %s", status)
	}

	return nil
}

// loaded returns nil when the running containerd has loaded a proxy
// snapshotter at the snapshotter's socket. containerd reads its config only
// when it starts, so what it loaded is asked of containerd on every sync, as
// nerdctl lists the snapshotters of its containerd, and not read from a
// config file, refer to
// https://github.com/containerd/nerdctl/blob/main/pkg/infoutil/infoutil.go.
func (i *Installer) loaded(ctx context.Context) error {
	conn, err := i.dial(i.cfg.NodeLabel.ContainerdAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := introspectionapi.NewIntrospectionClient(conn).Plugins(ctx, &introspectionapi.PluginsRequest{
		Filters: []string{"type==" + snapshotterPluginType},
	})
	if err != nil {
		return fmt.Errorf("list containerd snapshotters: %w", err)
	}

	socket, err := i.cfg.host(i.snapshotterAddr)
	if err != nil {
		return err
	}

	// containerd exports the address of a proxy plugin, whatever its name.
	// The addresses are compared as host paths, so another spelling of the
	// socket, as /var/run for /run, is the same one.
	for _, plugin := range resp.GetPlugins() {
		address := plugin.GetExports()["address"]
		if address == "" {
			continue
		}

		if path, err := i.cfg.host(address); err != nil || path != socket {
			continue
		}

		if initErr := plugin.GetInitErr(); initErr != nil {
			return fmt.Errorf("containerd failed to load snapshotter %s: %s", plugin.GetID(), initErr.GetMessage())
		}

		return nil
	}

	return fmt.Errorf("containerd has loaded no proxy snapshotter at %s", i.snapshotterAddr)
}

// dial returns a connection to a unix socket of the host, one per check as
// kubelet dials per gRPC probe, refer to
// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/probe/grpc/grpc.go.
func (i *Installer) dial(socket string) (*grpc.ClientConn, error) {
	socket, err := i.cfg.host(socket)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socket, err)
	}

	return conn, nil
}

// initKubeClient builds the client of the API server once.
func (i *Installer) initKubeClient() error {
	if i.kubeClient != nil {
		return nil
	}

	client, err := i.newKubeClient()
	if err != nil {
		return err
	}

	i.kubeClient = client
	return nil
}

// newKubeClient returns a client of the API server for the Pod's service
// account, as rest.InClusterConfig builds one, with the token directory the
// installer was given, refer to
// https://github.com/kubernetes/client-go/blob/master/rest/config.go.
func (i *Installer) newKubeClient() (kubernetes.Interface, error) {
	server, err := i.apiServer()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(&rest.Config{
		Host:            server,
		BearerTokenFile: filepath.Join(i.cfg.TokenDir, "token"),
		TLSClientConfig: rest.TLSClientConfig{CAFile: filepath.Join(i.cfg.TokenDir, "ca.crt")},
		QPS:             kubeQPS,
		Burst:           kubeBurst,
		Timeout:         requestTimeout,
	})
}
