package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/command"
	"github.com/containerd/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/logging"
	"github.com/containerd/nydus-snapshotter/config"
	"github.com/containerd/nydus-snapshotter/pkg/errdefs"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/containers/nydus-storage-plugin/pkg/fs"
	"github.com/containers/nydus-storage-plugin/pkg/manager"
	"github.com/containers/nydus-storage-plugin/pkg/services/keychain/dockerconfig"
	"github.com/containers/nydus-storage-plugin/pkg/services/resolver"
)

func waitForSIGINT() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

func main() {
	flags := command.NewFlags()
	app := &cli.App{
		Name:    "crio nydus store",
		Usage:   "crio nydus store plugin",
		Version: "0.0.0",
		Flags:   flags.F,
		Action: func(c *cli.Context) error {
			if err := logging.SetUp(flags.Args.LogLevel, flags.Args.LogToStdout, flags.Args.LogDir, flags.Args.RootDir); err != nil {
				return errors.Wrap(err, "failed to prepare logger")
			}

			var cfg config.Config
			if err := command.Validate(flags.Args, &cfg); err != nil {
				return errors.Wrap(err, "invalid argument")
			}

			mountPoint := fmt.Sprintf("%s/store", flags.Args.RootDir)
			if err := os.MkdirAll(mountPoint, 0755); err != nil {
				return errors.Wrap(err, "mkdir dir store failed")
			}

			// replace it with nydus-snapshotter resolver.
			hosts := resolver.RegistryHostsFromConfig([]resolver.Credential{dockerconfig.NewDockerconfigKeychain(c.Context)}...)
			layManager, err := manager.NewLayerManager(c.Context, flags.Args.RootDir, hosts, &cfg)
			if err != nil {
				panic(err)
			}

			if err := fs.Mount(c.Context, mountPoint, flags.Args.RootDir, true, layManager); err != nil {
				log.G(c.Context).WithError(err).Fatalf("failed to mount fs at %q", mountPoint)
			}
			defer func() {
				err := syscall.Unmount(mountPoint, 0)
				if err != nil {
					log.G(c.Context).Error(err)
				}
				log.G(c.Context).Info("Exiting")
			}()
			waitForSIGINT()
			return nil
		},
	}
	if err := app.Run(os.Args); err != nil {
		if errdefs.IsConnectionClosed(err) {
			log.L.Info("snapshotter exited")
			return
		}
		log.L.WithError(err).Fatal("failed to start crio nydus store")
	}
}
