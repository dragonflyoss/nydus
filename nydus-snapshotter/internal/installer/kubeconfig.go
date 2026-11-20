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
	"net"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

// syncKubeconfig copies the Pod's service account token and CA to the host
// and writes a kubeconfig reading them, for the snapshotter's secret
// informer; without kube_secret it does nothing, and no token is mounted.
// client-go re-reads a rotated token file, refer to
// https://github.com/kubernetes/client-go/blob/master/transport/token_source.go.
func (i *Installer) syncKubeconfig(ctx context.Context) error {
	enabled, err := i.kubeSecretEnabled()
	if err != nil {
		return err
	}

	if !enabled {
		return nil
	}

	dir := filepath.Dir(config.DefaultAuthKubeconfig)
	tokenPath, caPath := filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")
	kubeconfig, err := i.kubeconfig(tokenPath, caPath)
	if err != nil {
		return err
	}

	token, err := os.ReadFile(filepath.Join(i.cfg.TokenDir, "token"))
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	ca, err := os.ReadFile(filepath.Join(i.cfg.TokenDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read service account ca: %w", err)
	}

	// The token is a credential: keep it on tmpfs, in a dir only root reads.
	hostDir, err := i.cfg.host(dir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", hostDir, err)
	}

	// Write the token and CA before the kubeconfig naming them.
	return i.installFiles(ctx, []file{
		{path: tokenPath, perm: 0o600, data: token},
		{path: caPath, perm: 0o644, data: ca},
		{path: config.DefaultAuthKubeconfig, perm: 0o600, data: kubeconfig},
	})
}

// kubeconfig returns a kubeconfig that reaches the API server as in-cluster
// clients do and reads the token and the CA from host files, refer to
// https://github.com/kubernetes/client-go/blob/master/rest/config.go.
func (i *Installer) kubeconfig(tokenPath, caPath string) ([]byte, error) {
	server, err := i.apiServer()
	if err != nil {
		return nil, err
	}

	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"default": {
				Server:               server,
				CertificateAuthority: caPath,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"nydus-snapshotter": {
				TokenFile: tokenPath,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"default": {
				Cluster:  "default",
				AuthInfo: "nydus-snapshotter",
			},
		},
		CurrentContext: "default",
	})
	if err != nil {
		return nil, fmt.Errorf("encode kubeconfig: %w", err)
	}

	return kubeconfig, nil
}

// apiServer returns the address of the API server a Pod is given.
func (i *Installer) apiServer() (string, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return "", errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
	}

	return "https://" + net.JoinHostPort(host, port), nil
}

// kubeSecretEnabled reports whether the snapshotter reads credentials from
// secrets: by the payload config or, when the installer rejects that one, by
// the config installed on the host, which the running snapshotter keeps
// using. A broken ConfigMap must not stop the token rotation it relies on.
func (i *Installer) kubeSecretEnabled() (bool, error) {
	cfg, _, err := i.payloadConfig()
	if err == nil {
		return cfg.Auth.KubeSecret.Enable, nil
	}

	installed, installedErr := i.cfg.installed()
	if installedErr != nil {
		return false, err
	}

	return installed.Auth.KubeSecret.Enable, nil
}
