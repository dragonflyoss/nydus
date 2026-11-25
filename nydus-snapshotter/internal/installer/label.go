/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"fmt"
	"time"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	"github.com/containerd/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/kubeutil"
)

const (
	// NodeLabel is the label of a node whose Pods can use the snapshotter,
	// for Pods and RuntimeClasses to select.
	NodeLabel = "d7y.io/nydus-snapshotter"

	// nodeLabelValue is the value of NodeLabel.
	nodeLabelValue = "true"

	// snapshotterPluginType is the type containerd gives its snapshotters,
	// proxy plugins included.
	snapshotterPluginType = "io.containerd.snapshotter.v1"

	// servingTimeout is how long the install waits for the snapshotter it
	// started to serve, before a later sync labels the node instead.
	servingTimeout = 30 * time.Second

	// servingInterval is how often that wait checks the snapshotter.
	servingInterval = time.Second

	// requestTimeout bounds a call to the snapshotter and containerd.
	requestTimeout = 10 * time.Second
)

// syncNodeLabel makes NodeLabel follow whether Pods on the node can use the
// snapshotter. A check that fails removes the label, and the next one that
// passes adds it again. The label is kept when the installer stops: the
// DaemonSet controller deletes the Pods of a DaemonSet that selects the label
// from a node that loses it.
//
//	snapshotter SERVING ──┐
//	                      ├─▶ both ─▶ d7y.io/nydus-snapshotter=true
//	containerd loaded it ─┘   else ─▶ label removed
func (i *Installer) syncNodeLabel(ctx context.Context) error {
	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{"node": i.nodeName, "label": NodeLabel}))
	if err := i.checkNydusSnapshotterReady(ctx); err != nil {
		// A check cut short because the installer stops says nothing about
		// the node, and must not remove its label.
		if ctx.Err() != nil {
			return nil
		}

		log.G(ctx).WithError(err).Warn("node is not ready for the label")
		return i.removeNodeLabel(ctx)
	}

	return i.addNodeLabel(ctx)
}

// addNodeLabel adds NodeLabel to the node, which is patched only when its
// label differs, so a label changed behind the installer is put right. A
// label of another value is not the installer's, and is put right too.
func (i *Installer) addNodeLabel(ctx context.Context) error {
	value, _, err := i.nodeLabel(ctx)
	if err != nil {
		return err
	}

	if value == nodeLabelValue {
		return nil
	}

	if err := kubeutil.AddNodeLabel(ctx, i.kubeClient, i.nodeName, NodeLabel, nodeLabelValue); err != nil {
		return err
	}

	log.G(ctx).Info("labeled node")
	return nil
}

// removeNodeLabel removes NodeLabel from the node, which is patched only
// when it carries the label.
func (i *Installer) removeNodeLabel(ctx context.Context) error {
	_, labeled, err := i.nodeLabel(ctx)
	if err != nil {
		return err
	}

	if !labeled {
		return nil
	}

	if err := kubeutil.RemoveNodeLabel(ctx, i.kubeClient, i.nodeName, NodeLabel); err != nil {
		return err
	}

	log.G(ctx).Info("removed node label")
	return nil
}

// nodeLabel returns the value of NodeLabel on the node and whether the node
// carries it. A read at resource version 0 is answered from the cache of the
// API server; a stale answer costs one patch that changes nothing.
func (i *Installer) nodeLabel(ctx context.Context) (string, bool, error) {
	node, err := i.kubeClient.CoreV1().Nodes().Get(ctx, i.nodeName, metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return "", false, fmt.Errorf("get node %s: %w", i.nodeName, err)
	}

	value, labeled := node.Labels[NodeLabel]
	return value, labeled, nil
}

// waitForNydusSnapshotter waits for the snapshotter to serve, so the node is
// labeled right after the install and not a sync later.
func (i *Installer) waitForNydusSnapshotter(ctx context.Context) {
	// The poll fails only when the wait is over; the sync that follows
	// reports why.
	_ = wait.PollUntilContextTimeout(ctx, servingInterval, servingTimeout, true, func(ctx context.Context) (bool, error) {
		return i.checkNydusSnapshotterServing(ctx) == nil, nil
	})
}

// checkNydusSnapshotterReady checks that Pods on the node can use the
// snapshotter: it serves, and the running containerd has loaded it.
func (i *Installer) checkNydusSnapshotterReady(ctx context.Context) error {
	if err := i.checkNydusSnapshotterServing(ctx); err != nil {
		return err
	}

	return i.checkNydusSnapshotterLoaded(ctx)
}

// checkNydusSnapshotterServing checks that the snapshotter on the host
// answers its gRPC health check with SERVING.
func (i *Installer) checkNydusSnapshotterServing(ctx context.Context) error {
	conn, err := i.newGRPCClient(i.cfg.GRPC.Addr)
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

// checkNydusSnapshotterLoaded checks that the running containerd has loaded a
// proxy snapshotter at the snapshotter's socket. containerd reads its config
// only when it starts, so what it loaded is asked of containerd on every sync
// and not read from a config file.
func (i *Installer) checkNydusSnapshotterLoaded(ctx context.Context) error {
	conn, err := i.newGRPCClient(i.cfg.Containerd.Addr)
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

	containerSocket, err := i.containerPath(i.cfg.GRPC.Addr)
	if err != nil {
		return err
	}

	// containerd exports the address of a proxy plugin, whatever its name.
	// The addresses are compared as resolved container paths, so another
	// spelling of the socket, as /var/run for /run, is the same one.
	for _, plugin := range resp.GetPlugins() {
		address := plugin.GetExports()["address"]
		if address == "" {
			continue
		}

		if containerAddress, err := i.containerPath(address); err != nil || containerAddress != containerSocket {
			continue
		}

		if initErr := plugin.GetInitErr(); initErr != nil {
			return fmt.Errorf("containerd failed to load snapshotter %s: %s", plugin.GetID(), initErr.GetMessage())
		}

		return nil
	}

	return fmt.Errorf("containerd has loaded no proxy snapshotter at %s", i.cfg.GRPC.Addr)
}

// newGRPCClient returns a gRPC client of a unix socket of the host, one per
// check.
func (i *Installer) newGRPCClient(hostSocket string) (*grpc.ClientConn, error) {
	containerSocket, err := i.containerPath(hostSocket)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient("unix://"+containerSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("new grpc client %s: %w", hostSocket, err)
	}

	return conn, nil
}
