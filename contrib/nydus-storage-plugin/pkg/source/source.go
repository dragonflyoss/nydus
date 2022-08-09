package source

import (
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes/docker"
)

// Ported from stargz-snapshotter, copyright The stargz-snapshotter Authors.
// https://github.com/containerd/stargz-snapshotter/blob/923399007a8cde1ec871072ba6678b428b40b852/fs/source/source.go#L41
type RegistryHosts func(reference.Spec) ([]docker.RegistryHost, error)
