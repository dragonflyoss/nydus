/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package uninstaller removes what the installers left in the cluster, as
// helm keeps its uninstall action apart from its install action, refer to
// https://github.com/helm/helm/blob/v3.17.0/pkg/action/uninstall.go.
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/kubeutil"
)

const (
	// unlabelPatch removes installer.NodeLabel, which a node without it
	// accepts, refer to https://datatracker.ietf.org/doc/html/rfc7386.
	unlabelPatch = `{"metadata":{"labels":{"` + installer.NodeLabel + `":null}}}`
)

// Uninstaller removes what the installers left in the cluster: the
// installer.NodeLabel label of the nodes. A host keeps its snapshotter,
// which containers still run on.
type Uninstaller struct {
	// cfg is the config the uninstaller started with.
	cfg *config.Config

	// kubeClient is the client of the API server, which Run builds.
	kubeClient kubernetes.Interface
}

// New returns an uninstaller of the config.
func New(cfg *config.Config) *Uninstaller {
	return &Uninstaller{cfg: cfg}
}

// Run removes installer.NodeLabel from every node that carries it. It is the
// post-delete hook of the chart: an installer that stops keeps its label, so
// the uninstall removes them, as node-feature-discovery prunes its labels
// with such a hook, refer to
// https://github.com/kubernetes-sigs/node-feature-discovery/blob/master/deployment/helm/node-feature-discovery/templates/post-delete-job.yaml.
//
//	installer stops ─▶ label kept, the next installer Pod takes it over
//	helm uninstall ──▶ post-delete hook ─▶ Run ─▶ label removed
func (u *Uninstaller) Run(ctx context.Context) error {
	if u.kubeClient == nil {
		client, err := kubeutil.NewClient(u.cfg.Installer.TokenDir)
		if err != nil {
			return err
		}

		u.kubeClient = client
	}

	// List in pages, so the labeled nodes of a large cluster are never held
	// at once.
	nodes := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return u.kubeClient.CoreV1().Nodes().List(ctx, opts)
	})

	var errs []error
	if err := nodes.EachListItem(ctx, metav1.ListOptions{LabelSelector: installer.NodeLabel}, func(obj runtime.Object) error {
		node, err := meta.Accessor(obj)
		if err != nil {
			return err
		}

		// A node deleted since it was listed has no label left to remove.
		switch err := u.unlabelNode(ctx, node.GetName()); {
		case apierrors.IsNotFound(err):
		case err != nil:
			errs = append(errs, err)
		default:
			log.G(ctx).WithFields(log.Fields{"node": node.GetName(), "label": installer.NodeLabel}).Info("removed node label")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("list labeled nodes: %w", err)
	}

	return errors.Join(errs...)
}

// unlabelNode removes installer.NodeLabel from a node.
func (u *Uninstaller) unlabelNode(ctx context.Context, name string) error {
	if _, err := u.kubeClient.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, []byte(unlabelPatch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patch node %s: %w", name, err)
	}

	return nil
}
