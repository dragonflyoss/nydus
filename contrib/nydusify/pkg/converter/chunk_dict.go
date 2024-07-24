// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"fmt"
	"strings"
)

var (
	chunkDictFormats = []string{"bootstrap"}
	chunkDictSources = []string{"registry", "local"}
)

func isValidChunkDictFormat(s string) bool {
	for i := range chunkDictFormats {
		if chunkDictFormats[i] == s {
			return true
		}
	}
	return false
}

func isValidChunkDictSource(source string) bool {
	for i := range chunkDictSources {
		if chunkDictSources[i] == source {
			return true
		}
	}
	return false
}

// ParseChunkDictArgs parses chunk dict args like:
// - bootstrap:registry:$repo:$tag
// - bootstrap:local:$path
func ParseChunkDictArgs(args string) (format string, source string, ref string, err error) {
	names := strings.Split(args, ":")
	if len(names) < 3 {
		err = fmt.Errorf("invalid args")
		return
	}
	format = names[0]
	if !isValidChunkDictFormat(format) {
		err = fmt.Errorf("invalid chunk dict format %s, should be %v", format, chunkDictFormats)
		return
	}
	source = names[1]
	if !isValidChunkDictSource(source) {
		err = fmt.Errorf("invalid chunk dict source %s, should be %v", source, chunkDictSources)
		return
	}
	ref = strings.Join(names[2:], ":")
	return
}

type ChunkDictOpt struct {
	Args     string
	Insecure bool
}
