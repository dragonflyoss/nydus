/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package uninstaller removes what the installers left in the cluster.
package uninstaller

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/log"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/kubeutil"
)

// Uninstaller removes what the installers left in the cluster: the
// installer.NodeLabel label of the nodes. A host keeps its snapshotter,
// which containers still run on.
type Uninstaller struct {
	// kubeClient is the client of the API server the nodes are listed and
	// patched through.
	kubeClient kubernetes.Interface
}

// New returns an uninstaller that reaches the API server with the service
// account of the Pod. A client that cannot be built stops the uninstaller
// before it touches the cluster.
func New(cfg *config.Config) (*Uninstaller, error) {
	kubeClient, err := kubeutil.NewClient(cfg.Installer.ServiceAccountPath)
	if err != nil {
		return nil, err
	}

	return &Uninstaller{kubeClient: kubeClient}, nil
}

// Run removes installer.NodeLabel from every node that carries it. It is the
// post-delete hook of the chart: an installer that stops keeps its label, so
// the uninstall removes them.
//
//	installer stops ─▶ label kept, the next installer Pod takes it over
//	helm uninstall ──▶ post-delete hook ─▶ Run ─▶ label removed
func (u *Uninstaller) Run(ctx context.Context) error {
	// List in pages, so the labeled nodes of a large cluster are never held
	// at once.
	nodes := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return u.kubeClient.CoreV1().Nodes().List(ctx, opts)
	})

	// A node that fails does not hold up the others.
	var errs []error
	if err := nodes.EachListItem(ctx, metav1.ListOptions{LabelSelector: installer.NodeLabel}, func(obj runtime.Object) error {
		node, err := meta.Accessor(obj)
		if err != nil {
			return err
		}

		if err := u.removeNodeLabel(ctx, node.GetName()); err != nil {
			errs = append(errs, err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("list labeled nodes: %w", err)
	}

	return errors.Join(errs...)
}

// removeNodeLabel removes installer.NodeLabel from a node. A node deleted
// since it was listed has no label left to remove.
func (u *Uninstaller) removeNodeLabel(ctx context.Context, name string) error {
	if err := kubeutil.RemoveNodeLabel(ctx, u.kubeClient, name, installer.NodeLabel); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}

		return err
	}

	log.G(ctx).WithFields(log.Fields{"node": name, "label": installer.NodeLabel}).Info("removed node label")
	return nil
}
