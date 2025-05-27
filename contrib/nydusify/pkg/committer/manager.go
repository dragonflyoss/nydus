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
	// snapshot Mount Options[0] "workdir=$workdir", Options[1] "upperdir=$upperdir", Options[2] "lowerdir=$lowerdir".
	lowerDirs = strings.TrimPrefix(mount[0].Options[2], "lowerdir=")
	upperDir = strings.TrimPrefix(mount[0].Options[1], "upperdir=")

	return &InspectResult{
		LowerDirs: lowerDirs,
		UpperDir:  upperDir,
		Image:     image,
		Mounts:    mounts,
		Pid:       pid,
	}, nil
}
