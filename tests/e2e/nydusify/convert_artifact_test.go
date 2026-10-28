package nydusify

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestConvertArtifact(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	writer := os.Getenv("NYDUS_WRITER_BIN")
	env.Require(t, writer != "", "NYDUS_WRITER_BIN must point to the writer-fixture example")
	writer = env.RequireTool(t, writer)
	reg := registry.Start(t)
	unchanged := strings.Repeat("parent unchanged\n", 8192)
	src := inputTree(t, map[string]string{"changed": strings.Repeat("parent changed\n", 4096), "unchanged": unchanged})
	dir := env.WorkDir(t)
	parentBoot, parentBlobs := filepath.Join(dir, "parent.boot"), filepath.Join(dir, "parent-blobs")
	layout, err := fixture.LayoutByName("zstd")
	require.NoError(t, err)
	fixture.BuildInto(t, parentBlobs, parentBoot, src, layout)
	parentRef, childRef := reg.Ref("artifact", "parent"), reg.Ref("artifact", "child")
	nydusify(t, "convert", "--bootstrap", parentBoot, "--blob-dir", parentBlobs, "--target", parentRef,
		"--manifest-annotation", "org.example.parent=inherited")
	parent, err := remoteImage(t, parentRef).Manifest()
	require.NoError(t, err)
	require.Len(t, parent.Layers, 2)

	childDir := filepath.Join(dir, "child")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, writer, "--bootstrap", parentBoot, "--blob-dir", parentBlobs, "--output-dir", childDir).CombinedOutput()
	require.NoError(t, ctx.Err(), "%s", out)
	require.NoError(t, err, "incremental writer: %s", out)
	childBoot := filepath.Join(childDir, "image.boot")
	start := len(reg.Faults.Requests())
	nydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir, "--parent-image", parentRef,
		"--target", childRef, "--manifest-annotation", "org.example.child=new")
	for _, request := range reg.Faults.Requests()[start:] {
		require.False(t, request.Method == http.MethodGet &&
			request.Path == "/v2/artifact/blobs/"+parent.Layers[0].Digest.String(),
			"parent data must be reused by descriptor, not downloaded: %+v", request)
	}
	child, err := remoteImage(t, childRef).Manifest()
	require.NoError(t, err)
	require.Len(t, child.Layers, 3)
	require.Equal(t, parent.Layers[0], child.Layers[0])
	require.Equal(t, "inherited", child.Annotations["org.example.parent"])
	require.Equal(t, "new", child.Annotations["org.example.child"])
	entries := bootstrapEntries(t, remoteImage(t, childRef))
	require.Contains(t, entries, "image/"+parent.Layers[0].Digest.Hex+".blob.meta")
	require.Contains(t, entries, "image/"+child.Layers[1].Digest.Hex+".blob.meta")
	img := pullNydus(t, childRef, nil)
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	names, err := os.ReadDir(m.Root)
	require.NoError(t, err)
	require.Len(t, names, 3)
	for name, want := range map[string]string{"changed": "child changed\n", "created": "child created\n", "unchanged": unchanged} {
		data, err := os.ReadFile(filepath.Join(m.Root, name))
		require.NoError(t, err)
		require.Equal(t, want, string(data), "%s", name)
	}
	t.Run("CrossRepositoryParent", func(t *testing.T) {
		crossRef := reg.Ref("other-artifact", "child")
		nydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--parent-image", parentRef, "--target", crossRef)
		cross, err := remoteImage(t, crossRef).Manifest()
		require.NoError(t, err)
		require.Len(t, cross.Layers, 3)
		require.Equal(t, parent.Layers[0], cross.Layers[0])
		crossImage := pullNydus(t, crossRef, nil)
		crossMount := mount.Mount(t, mount.FUSE{}, crossImage, mount.Options{})
		for name, want := range map[string]string{
			"changed": "child changed\n", "created": "child created\n", "unchanged": unchanged,
		} {
			data, err := os.ReadFile(filepath.Join(crossMount.Root, name))
			require.NoError(t, err)
			require.Equal(t, want, string(data), "%s", name)
		}
	})
	t.Run("MissingParentBlob", func(t *testing.T) {
		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--target", reg.Ref("artifact", "missing"))
		require.Error(t, err, "%s", out)
		require.Contains(t, out, "missing nydus blob")
	})
}
