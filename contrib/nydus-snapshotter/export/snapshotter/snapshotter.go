package snapshotter

import (
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/snapshot"
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

			rs, err := snapshot.NewSnapshotter(ic.Context, cfg)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize snapshotter")
			}
			return rs, nil

		},
	})
}
