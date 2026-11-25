/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package uninstaller

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
)

var (
	mockLabels = map[string]string{"kept": "yes"}

	mockNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"kept": "yes"}}}

	mockLabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{"kept": "yes", installer.NodeLabel: "true"}}}

	mockOtherLabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2", Labels: map[string]string{"kept": "yes", installer.NodeLabel: "true"}}}

	mockUnlabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-3", Labels: map[string]string{"kept": "yes"}}}

	mockNodeNotFound = apierrors.NewNotFound(corev1.Resource("nodes"), "node-1")
)

func TestUninstaller_Run(t *testing.T) {
	tests := []struct {
		name   string
		nodes  []runtime.Object
		mock   func(u *Uninstaller, client *fake.Clientset)
		expect func(t *testing.T, client *fake.Clientset, verbs []string, err error)
	}{
		{
			name:  "remove the label from every node that carries it",
			nodes: []runtime.Object{mockLabeledNode, mockOtherLabeledNode, mockUnlabeledNode},
			mock:  func(u *Uninstaller, client *fake.Clientset) {},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, verbs)
				labeled, err := client.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: installer.NodeLabel})
				assert.NoError(err)
				assert.Empty(labeled.Items)
				nodes, err := client.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
				assert.NoError(err)
				for _, node := range nodes.Items {
					assert.Equal(mockLabels, node.Labels)
				}
			},
		},
		{
			name:  "leave a cluster without the label alone",
			nodes: []runtime.Object{mockNode, mockUnlabeledNode},
			mock:  func(u *Uninstaller, client *fake.Clientset) {},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list"}, verbs)
			},
		},
		{
			name:  "go on to the next node when a patch fails",
			nodes: []runtime.Object{mockLabeledNode, mockOtherLabeledNode},
			mock: func(u *Uninstaller, client *fake.Clientset) {
				failed := false
				client.PrependReactor("patch", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}

					failed = true
					return true, nil, errors.New("foo")
				})
			},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "patch node ")
				assert.ErrorContains(err, ": foo")
				assert.Equal([]string{"list", "patch", "patch"}, verbs)
				labeled, err := client.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: installer.NodeLabel})
				assert.NoError(err)
				assert.Len(labeled.Items, 1)
			},
		},
		{
			name:  "skip a node deleted since it was listed",
			nodes: []runtime.Object{mockLabeledNode, mockOtherLabeledNode},
			mock: func(u *Uninstaller, client *fake.Clientset) {
				failed := false
				client.PrependReactor("patch", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}

					failed = true
					return true, nil, mockNodeNotFound
				})
			},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, verbs)
			},
		},
		{
			name:  "nodes that cannot be listed",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(u *Uninstaller, client *fake.Clientset) {
				client.PrependReactor("list", "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("foo")
				})
			},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "list labeled nodes: foo")
				assert.Equal([]string{"list"}, verbs)
			},
		},
		{
			name:  "pod without an api server",
			nodes: []runtime.Object{mockLabeledNode},
			mock: func(u *Uninstaller, client *fake.Clientset) {
				u.kubeClient = nil
			},
			expect: func(t *testing.T, client *fake.Clientset, verbs []string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(verbs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			client := fake.NewClientset(tc.nodes...)
			u := New(config.New())
			u.kubeClient = client
			tc.mock(u, client)

			err := u.Run(t.Context())
			var verbs []string
			for _, action := range client.Actions() {
				verbs = append(verbs, action.GetVerb())
			}

			tc.expect(t, client, verbs, err)
		})
	}
}
