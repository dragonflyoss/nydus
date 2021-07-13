// Copyright 2021 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

type SourceReference struct {
	Reference string
	Digest    string
}

// BuildInfo provides trace information of current build environment,
// it should be recorded to target image manifest for easy image
// debugging and troubleshooting afterwards.
type BuildInfo struct {
	builderVersion  string
	nydusifyVersion string
	sourceReference SourceReference
}

func NewBuildInfo() *BuildInfo {
	return &BuildInfo{}
}

func (info *BuildInfo) SetBuilderVersion(val string) {
	info.builderVersion = val
}

func (info *BuildInfo) SetNydusifyVersion(val string) {
	info.nydusifyVersion = val
}

func (info *BuildInfo) SetSourceReference(val SourceReference) {
	info.sourceReference = val
}

func (info *BuildInfo) Dump() map[string]string {
	data := map[string]string{
		"nydus.trace.nydusify-version": info.nydusifyVersion,
		"nydus.trace.source-reference": info.sourceReference.Reference,
		"nydus.trace.source-digest":    info.sourceReference.Digest,
	}

	// In the case where all layers are hit by the build cache,
	// we may not get the builder version because the builder has never
	// been called. This version information is not really that important,
	// as a fallback, we can use Nydusify version to troubleshoot.
	if info.builderVersion != "" {
		data["nydus.trace.builder-version"] = info.builderVersion
	}

	return data
}
