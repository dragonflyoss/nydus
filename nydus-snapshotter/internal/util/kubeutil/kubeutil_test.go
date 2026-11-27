/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package kubeutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

var (
	mockNodeName = "node-1"

	mockLabelKey = "example.com/label"

	mockNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes"}}}

	mockLabeledNode = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mockNodeName, Labels: map[string]string{"kept": "yes", mockLabelKey: "false"}}}
)

func TestAPIServer(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		port   string
		expect func(t *testing.T, server string, err error)
	}{
		{
			name: "ipv4 host",
			host: "10.96.0.1",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://10.96.0.1:443", server)
			},
		},
		{
			name: "ipv6 host",
			host: "fd00::1",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("https://[fd00::1]:443", server)
			},
		},
		{
			name: "pod without a host",
			port: "443",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(server)
			},
		},
		{
			name: "pod without a port",
			host: "10.96.0.1",
			expect: func(t *testing.T, server string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Empty(server)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", tc.port)
			server, err := APIServer()
			tc.expect(t, server, err)
		})
	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		dir    string
		expect func(t *testing.T, client kubernetes.Interface, err error)
	}{
		{
			name: "client of the pod's api server",
			host: "10.96.0.1",
			dir:  filepath.Join("testdata", "serviceaccount"),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NotNil(client)
			},
		},
		{
			name: "ca that is no certificate",
			host: "10.96.0.1",
			dir:  filepath.Join("testdata", "serviceaccount-invalid-ca"),
			expect: func(t *testing.T, client kubernetes.Interface, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unable to load root certificates")
			},
		},
		{
			name: "pod without an api server",
			dir:  filepath.Join("testdata", "serviceaccount"),
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
			client, err := NewClient(tc.dir)
			tc.expect(t, client, err)
		})
	}
}

func TestAddNodeLabel(t *testing.T) {
	tests := []struct {
		name   string
		nodes  []runtime.Object
		expect func(t *testing.T, client *fake.Clientset, err error)
	}{
		{
			name:  "add the label to a node without it",
			nodes: []runtime.Object{mockNode},
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(map[string]string{"kept": "yes", mockLabelKey: "true"}, node.Labels)
			},
		},
		{
			name:  "replace another value of the label",
			nodes: []runtime.Object{mockLabeledNode},
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(map[string]string{"kept": "yes", mockLabelKey: "true"}, node.Labels)
			},
		},
		{
			name: "node that is missing",
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "patch node "+mockNodeName)
				assert.True(apierrors.IsNotFound(err))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset(tc.nodes...)

			tc.expect(t, client, AddNodeLabel(t.Context(), client, mockNodeName, mockLabelKey, "true"))
		})
	}
}

func TestRemoveNodeLabel(t *testing.T) {
	tests := []struct {
		name   string
		nodes  []runtime.Object
		expect func(t *testing.T, client *fake.Clientset, err error)
	}{
		{
			name:  "remove the label from a node that carries it",
			nodes: []runtime.Object{mockLabeledNode},
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(map[string]string{"kept": "yes"}, node.Labels)
			},
		},
		{
			name:  "accept a node without the label",
			nodes: []runtime.Object{mockNode},
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				node, err := client.CoreV1().Nodes().Get(t.Context(), mockNodeName, metav1.GetOptions{})
				assert.NoError(err)
				assert.Equal(map[string]string{"kept": "yes"}, node.Labels)
			},
		},
		{
			name: "node that is missing",
			expect: func(t *testing.T, client *fake.Clientset, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "patch node "+mockNodeName)
				assert.True(apierrors.IsNotFound(err))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset(tc.nodes...)

			tc.expect(t, client, RemoveNodeLabel(t.Context(), client, mockNodeName, mockLabelKey))
		})
	}
}
