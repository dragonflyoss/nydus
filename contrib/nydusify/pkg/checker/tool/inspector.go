// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

const (
	GetBlobs = iota
)

type InspectOption struct {
	Operation int
	Bootstrap string
}

type BlobInfo struct {
	BlobID          string `json:"blob_id"`
	CompressSize    uint64 `json:"compress_size"`
	DecompressSize  uint64 `json:"decompress_size"`
	ReadaheadOffset uint32 `json:"readahead_offset"`
	ReadaheadSize   uint32 `json:"readahead_size"`
}

type Inspector struct {
	binaryPath string
}

func NewInspector(binaryPath string) *Inspector {
	return &Inspector{binaryPath: binaryPath}
}

func (p *Inspector) Inspect(option InspectOption) (interface{}, error) {
	var (
		args []string
	)
	args = []string{
		"inspect",
		"--bootstrap",
		option.Bootstrap,
		"--request",
	}
	switch option.Operation {
	case GetBlobs:
		args = append(args, "blobs")
		cmd := exec.Command(p.binaryPath, args...)
		msg, err := cmd.CombinedOutput()
		if err != nil {
			return nil, err
		}
		var blobs []BlobInfo
		if err = json.Unmarshal(msg, &blobs); err != nil {
			return nil, err
		}
		return blobs, nil
	}
	return nil, fmt.Errorf("not support method %d", option.Operation)
}
