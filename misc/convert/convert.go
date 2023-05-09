// Copyright 2023 Ant Group. All rights reserved.
// Copyright 2023 Dalian University of Technology. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// The Convert-Ci CLI tool help we check if the zran, v5, v6 images work fine on conversion and run.
// We will use this tool in ci nightly.
// This tool depends on local nydusify, nydus-image.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v2"
)

var platform string = "linux/amd64,linux/arm64"

type Nydusify struct {
	// convert and check image
	Image string
	// remote target registry
	RemoteRegistry string
	// local target registry
	LocalRegistry string
	// v5 or v6 for rafs
	FsVersion string
	// oci-ref for zran
	OciRef bool
}

func main() {
	app := &cli.App{
		Name:  "Convert-Ci",
		Usage: "Convert ci tool used in dragonflyoss/image-service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "image",
				Required: true,
				Value:    "",
				Usage:    "Image used by nydusify",
			},
			&cli.StringFlag{
				Name:     "remote-registry",
				Required: true,
				Value:    "",
				Usage:    "Remote registry used by nydusify",
			},
			&cli.StringFlag{
				Name:     "local-registry",
				Required: false,
				Value:    "localhost:5000",
				Usage:    "Local registry used by nydusify",
			},
			&cli.StringFlag{
				Name:     "fs-version",
				Required: false,
				Value:    "6",
				Usage:    "Nydus image format version number, possible values: 5, 6",
			},
			&cli.BoolFlag{
				Name:     "oci-ref",
				Required: false,
				Value:    false,
				Usage:    "Convert to OCI-referenced nydus zran image",
			},
		},
		Action: func(c *cli.Context) error {
			nydusify := Nydusify{
				Image:          c.String("image"),
				RemoteRegistry: c.String("remote-registry"),
				LocalRegistry:  c.String("local-registry"),
				FsVersion:      c.String("fs-version"),
				OciRef:         c.Bool("oci-ref"),
			}
			nydusify.convert()
			nydusify.check()
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

// nydusify convert
func (nydusify *Nydusify) convert() {
	if nydusify.OciRef {
		nydusify.convertZran()
		return
	}
	cmd := make([]string, 0, 10)
	cmd = append(cmd, "--source", nydusify.Image)
	cmd = append(cmd, "--target", strings.Join([]string{nydusify.RemoteRegistry, nydusify.Image + ":nydus-nightly-v" + nydusify.FsVersion}, "/"))
	cmd = append(cmd, "--fs-version", nydusify.FsVersion)
	cmd = append(cmd, "--platform", platform)
	execConvert(cmd)
	//use local registry for speed
	cmd = make([]string, 0, 10)
	cmd = append(cmd, "--source", nydusify.Image)
	cmd = append(cmd, "--target", strings.Join([]string{nydusify.LocalRegistry, nydusify.Image + ":nydus-nightly-v" + nydusify.FsVersion}, "/"))
	cmd = append(cmd, "--fs-version", nydusify.FsVersion)
	cmd = append(cmd, "--platform", platform)
	execConvert(cmd)
}

// nydusify check
func (nydusify *Nydusify) check() {
	if nydusify.OciRef {
		cmd := make([]string, 0, 10)
		cmd = append(cmd, "--source", strings.Join([]string{nydusify.LocalRegistry, nydusify.Image}, "/"))
		cmd = append(cmd, "--target", strings.Join([]string{nydusify.LocalRegistry, nydusify.Image + ":nydus-nightly-oci-ref"}, "/"))
		execCheck(cmd)
		return
	}
	cmd := make([]string, 0, 10)
	cmd = append(cmd, "--source", nydusify.Image)
	cmd = append(cmd, "--target", strings.Join([]string{nydusify.RemoteRegistry, nydusify.Image + ":nydus-nightly-v" + nydusify.FsVersion}, "/"))
	execCheck(cmd)
}

// convert for zran is different with v5 and v6
func (nydusify *Nydusify) convertZran() {
	// for pre-built images
	cmd := make([]string, 0, 10)
	cmd = append(cmd, "--oci-ref")
	cmd = append(cmd, "--source", strings.Join([]string{nydusify.RemoteRegistry, nydusify.Image}, "/"))
	cmd = append(cmd, "--target", strings.Join([]string{nydusify.RemoteRegistry, nydusify.Image + ":nydus-nightly-oci-ref"}, "/"))
	cmd = append(cmd, "--platform", platform)
	execConvert(cmd)
	//use local registry for speed
	cmd = make([]string, 0, 10)
	cmd = append(cmd, "--oci-ref")
	cmd = append(cmd, "--source", strings.Join([]string{nydusify.LocalRegistry, nydusify.Image}, "/"))
	cmd = append(cmd, "--target", strings.Join([]string{nydusify.LocalRegistry, nydusify.Image + ":nydus-nightly-oci-ref"}, "/"))
	cmd = append(cmd, "--platform", platform)
	execConvert(cmd)
}

// exec convert command of nydusify
func execConvert(args []string) {
	cmd := []string{"sudo", "DOCKER_CONFIG=$HOME/.docker", "nydusify", "convert"}
	cmd = append(cmd, args...)
	fmt.Printf("%s\n", strings.Join(cmd, " "))

	err := executeCommand(cmd)
	if err != nil {
		panic(err)
	}
}

// exec check command of nydusify
func execCheck(args []string) {
	cmd := []string{"sudo", "DOCKER_CONFIG=$HOME/.docker", "nydusify", "check"}
	cmd = append(cmd, args...)
	fmt.Printf("%s\n", strings.Join(cmd, " "))
	err := executeCommand(cmd)
	if err != nil {
		panic(err)
	}
}

// exec the command
func executeCommand(command []string) error {
	cmd := exec.Command(command[0], command[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Print(stderr.String())
		return err
	}
	fmt.Print(stdout.String())
	return nil
}
