package snapshotter

import (
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/pkg/errors"

	"contrib/nydus-snapshotter/config"
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"contrib/nydus-snapshotter/pkg/filesystem/stargz"
	"contrib/nydus-snapshotter/snapshot"
)

const nydusDaemonConfigPath string = "/etc/nydus/config.json"
const snapshotterRootDir string = "/var/lib/containerd/io.containerd.snapshotter.v1.nydus"
const nydusdBinaryPath string = "/usr/local/bin/nydusd"

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.SnapshotPlugin,
		ID:   "nydus",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Platforms = append(ic.Meta.Platforms, platforms.DefaultSpec())

			cfg, err := defaultConfig()
			if err != nil {
				return nil, errors.Wrap(err, "failed to configure snapshotter")
			}

			fs, err := nydus.NewFileSystem(
				ic.Context,
				nydus.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
				nydus.WithMeta(cfg.RootDir),
				nydus.WithDaemonConfig(cfg.DaemonCfg),
				nydus.WithSharedDaemon(cfg.SharedDaemon),
			)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize nydus filesystem")
			}

			stargzFs, err := stargz.NewFileSystem(ic.Context)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize stargz filesystem")
			}

			return snapshot.NewSnapshotter(
				ic.Context,
				cfg.RootDir,
				cfg.NydusdBinaryPath,
				fs,
				stargzFs,
				snapshot.AsynchronousRemove)
		},
	})
}

func defaultConfig() (*config.Config, error) {
	var daemonCfg nydus.DaemonConfig
	if err := nydus.LoadConfig(nydusDaemonConfigPath, &daemonCfg); err != nil {
		return nil, errors.Wrapf(err, "failed to load config file %q", nydusDaemonConfigPath)
	}

	// TODO(renzhen): support passing config file when loading plugin
	return &config.Config{
		DaemonCfg:         daemonCfg,
		RootDir:           snapshotterRootDir,
		ValidateSignature: false,
		NydusdBinaryPath:  nydusdBinaryPath,
		SharedDaemon:      true,
	}, nil
}
