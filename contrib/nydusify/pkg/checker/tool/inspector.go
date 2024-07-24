// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/pkg/errors"
)

const (
	GetBlobs = iota
)

type InspectOption struct {
	Operation int
	Bootstrap string
}

type BlobInfo struct {
	BlobID           string `json:"blob_id"`
	CompressedSize   uint64 `json:"compressed_size"`
	DecompressedSize uint64 `json:"decompressed_size"`
	ReadaheadOffset  uint32 `json:"readahead_offset"`
	ReadaheadSize    uint32 `json:"readahead_size"`
}

func (info *BlobInfo) String() string {
	jsonBytes, _ := json.Marshal(info)
	return string(jsonBytes)
}

type BlobInfoList []BlobInfo

func (infos BlobInfoList) String() string {
	jsonBytes, _ := json.Marshal(&infos)
	return string(jsonBytes)
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
		option.Bootstrap,
		"--request",
	}
	switch option.Operation {
	case GetBlobs:
		args = append(args, "blobs")
		cmd := exec.Command(p.binaryPath, args...)
		msg, err := cmd.CombinedOutput()
		if err != nil {
			return nil, errors.Wrap(err, string(msg))
		}
		var blobs BlobInfoList
		if err = json.Unmarshal(msg, &blobs); err != nil {
			return nil, err
		}
		return blobs, nil
	}
	return nil, fmt.Errorf("not support method %d", option.Operation)
}
