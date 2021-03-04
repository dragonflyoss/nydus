package snapshotter

import (
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/pkg/errors"

	"contrib/nydus-snapshotter/config"
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"contrib/nydus-snapshotter/pkg/filesystem/stargz"
	"contrib/nydus-snapshotter/pkg/signature"
	"contrib/nydus-snapshotter/snapshot"
	"contrib/nydus-snapshotter/pkg/process"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:   plugin.SnapshotPlugin,
		ID:     "nydus",
		Config: &config.Config{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Platforms = append(ic.Meta.Platforms, platforms.DefaultSpec())

			cfg, ok := ic.Config.(*config.Config)
			if !ok {
				return nil, errors.New("invalid nydus snapshotter configuration")
			}

			if cfg.RootDir == "" {
				cfg.RootDir = ic.Root
			}
			if err := cfg.FillupWithDefaults(); err != nil {
				return nil, errors.New("failed to fillup nydus configuration with defaults")
			}

			verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize verifier")
			}

			mgr, err := process.NewManager(process.Opt{
				NydusdBinaryPath: cfg.NydusdBinaryPath,
				RootDir:          cfg.RootDir,
				SharedDaemon:     cfg.SharedDaemon,
			})
			if err != nil {
				return nil, errors.Wrap(err, "failed to new process manager")
			}

			fs, err := nydus.NewFileSystem(
				ic.Context,
				nydus.WithProcessManager(mgr),
				nydus.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
				nydus.WithMeta(cfg.RootDir),
				nydus.WithDaemonConfig(cfg.DaemonCfg),
				nydus.WithSharedDaemon(cfg.SharedDaemon),
				nydus.WithVerifier(verifier),
			)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize nydus filesystem")
			}

			stargzFs, err := stargz.NewFileSystem(
				ic.Context,
				stargz.WithProcessManager(mgr),
			)
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
