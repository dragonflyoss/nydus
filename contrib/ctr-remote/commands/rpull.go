/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/cmd/ctr/commands/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/labels"
	"github.com/containerd/containerd/log"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli"
)

const (
	remoteSnapshotterName     = "nydus"
	targetManifestDigestLabel = "containerd.io/snapshot/cri.manifest-digest"
)

var RpullCommand = cli.Command{
	Name:      "rpull",
	Usage:     "pull an image from a registry levaraging nydus snapshotter",
	ArgsUsage: "[flags] <ref>",
	Description: `Fetch and prepare an image for use in containerd levaraging nydus snapshotter.
After pulling an image, it should be ready to use the same reference in a run command.`,
	Flags: append(commands.RegistryFlags, commands.LabelFlag),
	Action: func(context *cli.Context) error {
		var (
			ref    = context.Args().First()
			config = &rPullConfig{}
		)
		if ref == "" {
			return fmt.Errorf("please provide an image reference to pull")
		}

		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		ctx, done, err := client.WithLease(ctx)
		if err != nil {
			return err
		}
		defer done(ctx)

		fc, err := content.NewFetchConfig(ctx, context)
		if err != nil {
			return err
		}
		config.FetchConfig = fc

		if err := pull(ctx, client, ref, config); err != nil {
			return err
		}
		return nil
	},
}

type rPullConfig struct {
	*content.FetchConfig
}

func pull(ctx context.Context, client *containerd.Client, ref string, config *rPullConfig) error {
	pCtx := ctx
	h := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
			fmt.Printf("fetching %v... %v\n", desc.Digest.String()[:15], desc.MediaType)
		}
		return nil, nil
	})

	log.G(pCtx).WithField("image", ref).Debug("fetching")
	configLabels := commands.LabelArgs(config.Labels)
	if _, err := client.Pull(pCtx, ref, []containerd.RemoteOpt{
		containerd.WithPullLabels(configLabels),
		containerd.WithResolver(config.Resolver),
		containerd.WithImageHandler(h),
		containerd.WithSchema1Conversion,
		containerd.WithPullUnpack,
		containerd.WithPullSnapshotter(remoteSnapshotterName),
		containerd.WithImageHandlerWrapper(appendDefaultLabelsHandlerWrapper(ref)),
	}...); err != nil {
		return err
	}

	return nil
}

func appendDefaultLabelsHandlerWrapper(ref string) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := f.Handle(ctx, desc)
			if err != nil {
				return nil, err
			}
			switch desc.MediaType {
			case ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2Manifest:
				for i := range children {
					c := &children[i]
					if images.IsLayerType(c.MediaType) {
						if c.Annotations == nil {
							c.Annotations = make(map[string]string)
						}
						c.Annotations[label.ImageRef] = ref
						c.Annotations[label.CRIDigest] = c.Digest.String()
						var layers string
						for _, l := range children[i:] {
							if images.IsLayerType(l.MediaType) {
								ls := fmt.Sprintf("%s,", l.Digest.String())
								// This avoids the label hits the size limitation.
								// Skipping layers is allowed here and only affects performance.
								if err := labels.Validate(label.NydusDataLayer, layers+ls); err != nil {
									break
								}
								layers += ls
							}
						}
						c.Annotations[label.CRIImageLayer] = strings.TrimSuffix(layers, ",")
						c.Annotations[targetManifestDigestLabel] = desc.Digest.String()
					}
				}
			}
			return children, nil
		})
	}
}
