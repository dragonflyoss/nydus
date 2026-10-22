package nydusify

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func TestConvertInputs(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	t.Run("LocalDirectory", func(t *testing.T) {
		t.Parallel()
		src := inputTree(t, map[string]string{"keep": "kept\n", "bundle": "bootstrap only\n"})
		ref := reg.Ref("local", "nydus")
		nydusify(t, "convert", "--source", src, "--target", ref,
			"--append-in-bootstrap", filepath.Join(src, "bundle"), "--manifest-annotation", "org.example.test=local")
		remoteImg := remoteImage(t, ref)
		manifest, err := remoteImg.Manifest()
		require.NoError(t, err)
		require.Equal(t, "local", manifest.Annotations["org.example.test"])
		require.Equal(t, []byte("bootstrap only\n"), bootstrapEntries(t, remoteImg)["image/bundle"])
		want := slices.DeleteFunc(oracle.ScanSource(t, src), func(e oracle.Entry) bool { return string(e.Path) == "bundle" })
		img := pullNydus(t, ref, want)
		require.Len(t, img.Blobs, 1)
		m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
		oracle.VerifyMount(t, m.Root, want, oracle.CompareOptions{Nlink: true})
	})

	t.Run("MixedSources", func(t *testing.T) {
		t.Parallel()
		base := inputTree(t, map[string]string{"value": "base", "remove": "removed", "base": "base"})
		middle := inputTree(t, map[string]string{"value": "middle", ".wh.remove": "", "middle": "middle"})
		upper := inputTree(t, map[string]string{"value": "upper", "upper": "upper"})
		top := inputTree(t, map[string]string{"value": "top", "top": "top"})
		middleRef, upperOCI := reg.Ref("mixed", "middle"), reg.Ref("mixed", "upper-oci")
		reg.PushDirs(t, middleRef, middle)
		image := reg.PushDirs(t, upperOCI, upper)
		cfg, err := image.ConfigFile()
		require.NoError(t, err)
		cfg = cfg.DeepCopy()
		cfg.Config.Env = []string{"SOURCE=upper"}
		cfg.Config.Entrypoint = []string{"/upper"}
		image, err = mutate.ConfigFile(image, cfg)
		require.NoError(t, err)
		parsed, err := name.ParseReference(upperOCI, name.Insecure)
		require.NoError(t, err)
		require.NoError(t, remote.Write(parsed, image))
		upperRef := reg.Ref("mixed", "upper-nydus")
		nydusify(t, "convert", "--source", upperOCI, "--target", upperRef)
		target := reg.Ref("mixed", "result")
		nydusify(t, "convert", "--source", base, "--source", middleRef, "--source", upperRef,
			"--source", top, "--target", target, "--manifest-annotation", "org.example.test=mixed")
		want := newSource(t, "mixed", base, middle, upper, top)
		img := pullNydus(t, target, want.want)
		require.Len(t, img.Blobs, 4)
		m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
		oracle.VerifyMount(t, m.Root, want.want, want.compare())
		result := remoteImage(t, target)
		got, err := result.ConfigFile()
		require.NoError(t, err)
		require.Equal(t, cfg.Config.Env, got.Config.Env)
		require.Equal(t, cfg.Config.Entrypoint, got.Config.Entrypoint)
		manifest, err := result.Manifest()
		require.NoError(t, err)
		require.Equal(t, "mixed", manifest.Annotations["org.example.test"])
	})
}
