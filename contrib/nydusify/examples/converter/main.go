package main

import (
	"context"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter"
)

func main() {
	// Configurable parameters for converter
	workDir := "./tmp"
	nydusImagePath := "/path/to/nydus-image"
	source := "localhost:5000/ubuntu:latest"
	target := "localhost:5000/ubuntu:latest-nydus"

	opt := converter.Opt{
		Platforms:      "linux/amd64",
		Source:         source,
		Target:         target,
		SourceInsecure: true,
		TargetInsecure: true,

		WorkDir:          workDir,
		PrefetchPatterns: "/",
		NydusImagePath:   nydusImagePath,
		MergePlatform:    false,
		Docker2OCI:       true,
	}

	if err := converter.Convert(context.Background(), opt); err != nil {
		panic(err)
	}
}
