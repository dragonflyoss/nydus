package main

import (
	"context"

	"contrib/nydusify/pkg/converter"
	"contrib/nydusify/pkg/converter/provider"
)

func main() {
	// Configurable parameters for converter
	wordDir := "./tmp"
	nydusImagePath := "/path/to/nydus-image"
	source := "localhost:5000"
	target := "localhost:5000/latest-nydus"
	auth := "<base64_encoded_auth>"
	insecure := true

	// Logger outputs Nydus image conversion progress
	logger, err := provider.DefaultLogger()
	if err != nil {
		panic(err)
	}

	// Create remote with auth string for registry communication
	sourceRemote, err := provider.DefaultRemoteWithAuth(source, insecure, auth)
	if err != nil {
		panic(err)
	}
	// Or we can create with docker config
	// sourceRemote, err := provider.DefaultRemote(source, insecure)
	// if err != nil {
	// 	panic(err)
	// }
	targetRemote, err := provider.DefaultRemoteWithAuth(target, insecure, auth)
	if err != nil {
		panic(err)
	}

	// Source provider gets source image manifest, config, and layer
	sourceProvider, err := provider.DefaultSource(context.Background(), sourceRemote, wordDir)
	if err != nil {
		panic(err)
	}

	opt := converter.Opt{
		Logger:         logger,
		SourceProvider: sourceProvider,
		TargetRemote:   targetRemote,

		WorkDir:        wordDir,
		PrefetchDir:    "/",
		NydusImagePath: nydusImagePath,
		MultiPlatform:  false,
		DockerV2Format: true,
		WhiteoutSpec:   "oci",
	}

	cvt, err := converter.New(opt)
	if err != nil {
		panic(err)
	}

	if err := cvt.Convert(context.Background()); err != nil {
		panic(err)
	}
}
