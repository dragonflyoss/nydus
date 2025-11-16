// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package committer

import (
	"context"
	"encoding/json"
	"strings"

	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/pkg/errors"
)

type InspectResult struct {
	LowerDirs string
	UpperDir  string
	Image     string
	Mounts    []Mount
	Pid       int
}

type Mount struct {
	Destination string
	Source      string
}

type Manager struct {
	address string
}

func NewManager(addr string) (*Manager, error) {
	return &Manager{
		address: addr,
	}, nil
}

func (m *Manager) Pause(ctx context.Context, containerID string) error {
	client, err := containerdclient.New(m.address)
	if err != nil {
		return errors.Wrapf(err, "create client")
	}
	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return errors.Wrapf(err, "load container")
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return errors.Wrapf(err, "obtain container task")
	}

	return task.Pause(ctx)
}

func (m *Manager) UnPause(ctx context.Context, containerID string) error {
	client, err := containerdclient.New(m.address)
	if err != nil {
		return errors.Wrapf(err, "create client")
	}
	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return errors.Wrapf(err, "load container")
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return errors.Wrapf(err, "obtain container task")
	}

	return task.Resume(ctx)
}

func (m *Manager) Inspect(ctx context.Context, containerID string) (*InspectResult, error) {
	client, err := containerdclient.New(m.address)
	if err != nil {
		return nil, errors.Wrapf(err, "create client")
	}
	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return nil, errors.Wrapf(err, "load container")
	}
	_image, err := container.Image(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "obtain container image")
	}
	image := _image.Name()

	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "obtain container task")
	}
	pid := int(task.Pid())

	containerInfo, err := container.Info(ctx, containerdclient.WithoutRefreshedMetadata)
	if err != nil {
		return nil, errors.Wrapf(err, "obtain container info")
	}
	spec := oci.Spec{}
	if err := json.Unmarshal(containerInfo.Spec.GetValue(), &spec); err != nil {
		return nil, errors.Wrapf(err, "unmarshal json")
	}
	mounts := []Mount{}
	for _, mount := range spec.Mounts {
		mounts = append(mounts, Mount{
			Destination: mount.Destination,
			Source:      mount.Source,
		})
	}

	snapshot := client.SnapshotService("nydus")
	lowerDirs := ""
	upperDir := ""
	mount, err := snapshot.Mounts(ctx, containerInfo.SnapshotKey)
	if err != nil {
		return nil, errors.Wrapf(err, "get snapshot mount")
	}

	// Parse overlay mount options properly - they can be in any order
	for _, option := range mount[0].Options {
		if strings.HasPrefix(option, "lowerdir=") {
			lowerDirs = strings.TrimPrefix(option, "lowerdir=")
		} else if strings.HasPrefix(option, "upperdir=") {
			upperDir = strings.TrimPrefix(option, "upperdir=")
		}
		// Skip workdir and other options as they're not needed
	}

	return &InspectResult{
		LowerDirs: lowerDirs,
		UpperDir:  upperDir,
		Image:     image,
		Mounts:    mounts,
		Pid:       pid,
	}, nil
}
