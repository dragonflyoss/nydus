package nydusify

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func TestConvertIndex(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"shared": "same layer across architectures\n"})
	base := reg.PushDirs(t, reg.Ref("index", "seed"), src)
	var index v1.ImageIndex = empty.Index
	for _, arch := range []string{"amd64", "arm64"} {
		cfg, err := base.ConfigFile()
		require.NoError(t, err)
		cfg = cfg.DeepCopy()
		cfg.Architecture = arch
		cfg.Config.Env = []string{"ARCH=" + arch}
		image, err := mutate.ConfigFile(base, cfg)
		require.NoError(t, err)
		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	source := reg.Ref("index", "source")
	ref, err := name.ParseReference(source, name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, index))
	for _, filter := range []string{"all", "arm64"} {
		t.Run(filter, func(t *testing.T) {
			t.Parallel()
			target := reg.Ref("index", filter)
			args := []string{"convert", "--source", source, "--target", target}
			if filter != "all" {
				args = append(args, "--platform", "linux/"+filter)
			}
			nydusify(t, args...)
			targetRef, err := name.ParseReference(target, name.Insecure)
			require.NoError(t, err)
			root, err := remote.Get(targetRef)
			require.NoError(t, err)
			var children []v1.Descriptor
			if filter == "all" {
				require.True(t, root.MediaType.IsIndex())
				converted, err := root.ImageIndex()
				require.NoError(t, err)
				manifest, err := converted.IndexManifest()
				require.NoError(t, err)
				require.Len(t, manifest.Manifests, 2)
				children = manifest.Manifests
			} else {
				require.True(t, root.MediaType.IsImage(), "one selected platform collapses to a manifest")
				child := root.Descriptor
				child.Platform = &v1.Platform{OS: "linux", Architecture: filter}
				children = []v1.Descriptor{child}
			}
			var sharedBlob v1.Hash
			for _, desc := range children {
				require.NotNil(t, desc.Platform)
				if filter != "all" {
					require.Equal(t, filter, desc.Platform.Architecture)
				}
				childRef := targetRef.Context().Digest(desc.Digest.String()).String()
				image := remoteImage(t, childRef)
				cfg, err := image.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, desc.Platform.Architecture, cfg.Architecture)
				require.Equal(t, []string{"ARCH=" + cfg.Architecture}, cfg.Config.Env)
				child, err := image.Manifest()
				require.NoError(t, err)
				require.Len(t, child.Layers, 2)
				if sharedBlob.Hex != "" {
					require.Equal(t, sharedBlob, child.Layers[0].Digest, "shared source layer must remain shared")
				}
				sharedBlob = child.Layers[0].Digest
				img := pullNydus(t, childRef, oracle.ScanSource(t, src))
				m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
				m.Unmount()
			}
			reused := reg.Ref("index", filter+"-reused")
			nydusify(t, "convert", "--source", target, "--target", reused)
			reusedRef, err := name.ParseReference(reused, name.Insecure)
			require.NoError(t, err)
			got, err := remote.Head(reusedRef)
			require.NoError(t, err)
			want, err := remote.Head(targetRef)
			require.NoError(t, err)
			require.Equal(t, want.Digest, got.Digest, "already converted index must be reused")
		})
	}
}
