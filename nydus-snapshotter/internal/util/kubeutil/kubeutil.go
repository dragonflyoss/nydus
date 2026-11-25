/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package kubeutil holds the Kubernetes client code that the installer and
// the uninstaller share.
package kubeutil

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// qps is the rate of the requests to the API server, kubelet's default,
	// so the uninstaller clears 5000 nodes within the five minutes helm gives
	// a hook.
	qps = 50

	// burst is the burst of those requests, kubelet's default.
	burst = 100

	// requestTimeout bounds a call to the API server.
	requestTimeout = 10 * time.Second
)

// APIServer returns the address of the API server a Pod is given.
func APIServer() (string, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
	}

	return "https://" + net.JoinHostPort(host, port), nil
}

// NewClient returns a client of the API server for the Pod's service account,
// whose token and CA are in serviceAccountPath, as rest.InClusterConfig
// builds one for the default directory.
func NewClient(serviceAccountPath string) (kubernetes.Interface, error) {
	server, err := APIServer()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(&rest.Config{
		Host:            server,
		BearerTokenFile: filepath.Join(serviceAccountPath, "token"),
		TLSClientConfig: rest.TLSClientConfig{CAFile: filepath.Join(serviceAccountPath, "ca.crt")},
		QPS:             qps,
		Burst:           burst,
		Timeout:         requestTimeout,
	})
}
