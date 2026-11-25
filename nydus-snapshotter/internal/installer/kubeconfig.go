/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/kubeutil"
)

// syncKubeconfig copies the Pod's service account token and CA to the host
// and writes a kubeconfig reading them, for the snapshotter's secret
// informer. client-go re-reads a rotated token file.
func (i *Installer) syncKubeconfig(ctx context.Context) error {
	hostDir := filepath.Dir(i.cfg.Auth.KubeSecret.Kubeconfig)
	tokenPath, caPath := filepath.Join(hostDir, "token"), filepath.Join(hostDir, "ca.crt")
	kubeconfig, err := i.kubeconfig(tokenPath, caPath)
	if err != nil {
		return err
	}

	token, err := os.ReadFile(filepath.Join(i.cfg.Installer.ServiceAccountPath, "token"))
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	ca, err := os.ReadFile(filepath.Join(i.cfg.Installer.ServiceAccountPath, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read service account ca: %w", err)
	}

	// The token is a credential: keep it in a dir only root reads.
	containerDir, err := i.containerPath(hostDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", containerDir, err)
	}

	// Write the token and CA before the kubeconfig naming them.
	return i.installFiles(ctx, []file{
		{hostPath: tokenPath, perm: 0o600, data: token},
		{hostPath: caPath, perm: 0o644, data: ca},
		{hostPath: i.cfg.Auth.KubeSecret.Kubeconfig, perm: 0o600, data: kubeconfig},
	})
}

// kubeconfig returns a kubeconfig that reaches the API server as in-cluster
// clients do and reads the token and the CA from host files.
func (i *Installer) kubeconfig(tokenPath, caPath string) ([]byte, error) {
	server, err := kubeutil.APIServer()
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
