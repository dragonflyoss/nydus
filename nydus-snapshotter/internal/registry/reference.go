/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package registry turns image references and certs.d hosts.toml files into
// the registry endpoint a nydus daemon reads blobs from.
package registry

import (
	"fmt"

	"github.com/distribution/reference"
)

// Reference is an image reference split into what a daemon needs.
type Reference struct {
	// Name is the normalized reference, e.g. docker.io/library/ubuntu:24.04.
	Name string

	// Host is the registry host as named by the reference, e.g. docker.io.
	Host string

	// Repository is the repository path, e.g. library/ubuntu.
	Repository string
}

// ParseReference parses and normalizes an image reference as docker and
// containerd do.
func ParseReference(ref string) (*Reference, error) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", ref, err)
	}

	return &Reference{
		Name:       named.String(),
		Host:       reference.Domain(named),
		Repository: reference.Path(named),
	}, nil
}
