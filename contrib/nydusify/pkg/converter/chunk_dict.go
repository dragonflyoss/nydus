// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

var (
	supportChunkDictTypes = []string{"bootstrap"}
	supportChunkDictFrom  = []string{"registry", "local"}
)

// only support bootstrap now
func isValidChunkDictType(s string) bool {
	for i := range supportChunkDictTypes {
		if supportChunkDictTypes[i] == s {
			return true
		}
	}
	return false
}

func isValidFrom(from string) bool {
	for i := range supportChunkDictFrom {
		if supportChunkDictFrom[i] == from {
			return true
		}
	}
	return false
}

func parseArgs(args string) (chunkDictType string, from string, info string, err error) {
	names := strings.Split(args, ":")
	if len(names) < 3 {
		err = fmt.Errorf("invalid args")
		return
	}
	chunkDictType = names[0]
	if !isValidChunkDictType(chunkDictType) {
		err = fmt.Errorf("invalid chunk dict type %s, should be %v", chunkDictType, supportChunkDictTypes)
		return
	}
	from = names[1]
	if !isValidFrom(from) {
		err = fmt.Errorf("invalid chunk dict from %s, should be %v", from, supportChunkDictFrom)
		return
	}
	info = strings.Join(names[2:], ":")
	return
}

func getChunkDictFromRegistry(prepareDir, imageName string, insecure bool, platform string) (string, error) {
	// get bootstrap from registry
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // 5 minutes timout
	defer cancel()
	r, err := provider.DefaultRemote(imageName, insecure)
	if err != nil {
		return "", err
	}
	p, err := parser.New(r, platform)
	if err != nil {
		return "", err
	}
	parsed, err := p.Parse(timeoutCtx)
	if err != nil {
		return "", err
	}
	targetFile := filepath.Join(prepareDir, "image.boot")
	rc, err := p.PullNydusBootstrap(timeoutCtx, parsed.NydusImage)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	if err = utils.UnpackFile(rc, utils.BootstrapFileNameInLayer, targetFile); err != nil {
		return "", err
	}
	return targetFile, nil
}

func (cvt *Converter) prepareBootstrap(prepareDir, from, info string) (string, []string, error) {
	var (
		target string
		err    error
	)
	if from == "local" {
		target = info
	} else {
		_, arch, err := provider.ExtractOsArch(cvt.chunkDict.Platform)
		if err != nil {
			return "", []string{}, err
		}
		target, err = getChunkDictFromRegistry(prepareDir, info, cvt.chunkDict.Insecure, arch)
		if err != nil {
			return "", []string{}, err
		}
	}
	debugOutput := filepath.Join(prepareDir, "check.output")
	// check
	if err = tool.NewBuilder(cvt.NydusImagePath).Check(tool.BuilderOption{
		BootstrapPath:   target,
		DebugOutputPath: debugOutput,
	}); err != nil {
		return "", []string{}, fmt.Errorf("invalid bootstrap format %v", err)
	}

	item, err := tool.NewInspector(cvt.NydusImagePath).Inspect(tool.InspectOption{
		Operation: tool.GetBlobs,
		Bootstrap: target,
	})
	if err != nil {
		return "", []string{}, err
	}
	blobsInfo, _ := item.([]tool.BlobInfo)
	var blobs []string
	for _, blobInfo := range blobsInfo {
		blobs = append(blobs, blobInfo.BlobID)
	}
	logrus.Infof("chunk dict has blobs %v", blobs)
	return "bootstrap=" + target, blobs, nil
}

type ChunkDictOpt struct {
	Args     string
	Insecure bool
	Platform string
}

// PrepareChunkDict prepare ChunkDict under $work_dir/chunk_dict/
// args:
// support type:registry:$repo:$tag or type:local:$path
// return
// type=$path, which could be used as a command-line argument of nydus-image
// blobs we need add blobs which are belongs to chunk dict to bootstrap manifests
func (cvt *Converter) prepareChunkDict() (string, []string, error) {
	// prepare dir
	prepareDir := filepath.Join(cvt.WorkDir, "chunk_dict")
	err := os.MkdirAll(prepareDir, 0755)
	if err != nil {
		return "", []string{}, err
	}
	cType, from, info, err := parseArgs(cvt.chunkDict.Args)
	if err != nil {
		return "", []string{}, err
	}
	switch cType {
	case "bootstrap":
		return cvt.prepareBootstrap(prepareDir, from, info)
	}
	return "", []string{}, fmt.Errorf("invalid type %s", cType)
}
