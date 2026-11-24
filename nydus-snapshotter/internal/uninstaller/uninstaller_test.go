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

type mockCluster struct {
	client *fake.Clientset
}

func (c *mockCluster) verbs() []string {
	verbs := []string{}
	for _, action := range c.client.Actions() {
		verbs = append(verbs, action.GetVerb())
	}

	return verbs
}

func (c *mockCluster) nodes(t *testing.T, selector string) []corev1.Node {
	t.Helper()
	nodes, err := c.client.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: selector})
	assert.NoError(t, err)
	return nodes.Items
}

func (c *mockCluster) fail(verb string, err error) {
	failed := false
	c.client.PrependReactor(verb, "nodes", func(clienttesting.Action) (bool, runtime.Object, error) {
		if failed {
			return false, nil, nil
		}

		failed = true
		return true, nil, err
	})
}

func newMockCluster(t *testing.T, nodes ...*corev1.Node) *mockCluster {
	t.Helper()
	c := &mockCluster{client: fake.NewClientset()}
	for _, node := range nodes {
		_, err := c.client.CoreV1().Nodes().Create(t.Context(), node.DeepCopy(), metav1.CreateOptions{})
		assert.NoError(t, err)
	}
	c.client.ClearActions()

	return c
}

func TestUninstaller_Run(t *testing.T) {
	tests := []struct {
		name    string
		nodes   []*corev1.Node
		prepare func(t *testing.T, u *Uninstaller, c *mockCluster)
		expect  func(t *testing.T, c *mockCluster, err error)
	}{
		{
			name:    "remove the label from every node that carries it",
			nodes:   []*corev1.Node{mockLabeledNode, mockOtherLabeledNode, mockUnlabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, c.verbs())
				assert.Empty(c.nodes(t, installer.NodeLabel))
				for _, node := range c.nodes(t, "") {
					assert.Equal(mockLabels, node.Labels)
				}
			},
		},
		{
			name:    "leave a cluster without the label alone",
			nodes:   []*corev1.Node{mockNode, mockUnlabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list"}, c.verbs())
			},
		},
		{
			name:  "go on to the next node when a patch fails",
			nodes: []*corev1.Node{mockLabeledNode, mockOtherLabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {
				c.fail("patch", errors.New("foo"))
			},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "patch node ")
				assert.ErrorContains(err, ": foo")
				assert.Equal([]string{"list", "patch", "patch"}, c.verbs())
				assert.Len(c.nodes(t, installer.NodeLabel), 1)
			},
		},
		{
			name:  "skip a node deleted since it was listed",
			nodes: []*corev1.Node{mockLabeledNode, mockOtherLabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {
				c.fail("patch", mockNodeNotFound)
			},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"list", "patch", "patch"}, c.verbs())
			},
		},
		{
			name:  "nodes that cannot be listed",
			nodes: []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {
				c.fail("list", errors.New("foo"))
			},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "list labeled nodes: foo")
				assert.Equal([]string{"list"}, c.verbs())
			},
		},
		{
			name:  "pod without an api server",
			nodes: []*corev1.Node{mockLabeledNode},
			prepare: func(t *testing.T, u *Uninstaller, c *mockCluster) {
				u.kubeClient = nil
			},
			expect: func(t *testing.T, c *mockCluster, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(c.verbs())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			c := newMockCluster(t, tc.nodes...)
			u := New(config.New())
			u.kubeClient = c.client
			tc.prepare(t, u, c)
			tc.expect(t, c, u.Run(t.Context()))
		})
	}
}
