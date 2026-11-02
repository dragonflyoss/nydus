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
	parentBlob, _ := fixture.BuildInto(t, parentBlobs, parentBoot, src, layout)
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
	t.Run("PruneUnusedDevice", func(t *testing.T) {
		work := env.WorkDir(t)
		obsolete := inputTree(t, map[string]string{"changed": "obsolete changed", "unchanged": "obsolete unchanged"})
		deadBlob, _ := fixture.BuildInto(t, filepath.Join(work, "dead-blobs"), filepath.Join(work, "dead.boot"), obsolete, layout)
		boot := filepath.Join(work, "image.boot")
		mergeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := exec.CommandContext(mergeCtx, env.Nydus(t), "merge", deadBlob, parentBlob, "--bootstrap", boot).CombinedOutput()
		require.NoError(t, err, "%s", out)
		original, err := os.ReadFile(boot)
		require.NoError(t, err)
		ref := reg.Ref("artifact", "pruned")
		// Do not supply the dead blob: pruning needs its references, not its data.
		nydusify(t, "convert", "--bootstrap", boot, "--blob", parentBlob, "--prune",
			"--output-bootstrap", boot, "--target", ref)
		published := remoteImage(t, ref)
		manifest, err := published.Manifest()
		require.NoError(t, err)
		require.Len(t, manifest.Layers, 2)
		require.Equal(t, parent.Layers[0].Digest, manifest.Layers[0].Digest)
		final, err := os.ReadFile(boot)
		require.NoError(t, err)
		require.NotEqual(t, original, final, "prune must rewrite the device table")
		require.Equal(t, bootstrapEntries(t, published)[bootstrapInLayer], final)
		pruned := mount.Mount(t, mount.FUSE{}, pullNydus(t, ref, nil), mount.Options{})
		for _, name := range []string{"changed", "unchanged"} {
			want, err := os.ReadFile(filepath.Join(src, name))
			require.NoError(t, err)
			got, err := os.ReadFile(pruned.Path(name))
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	})
	for _, tc := range []struct {
		name    string
		limit   string
		compact bool
	}{
		{"ExportWithoutCompact", "2", false},
		{"RemoteParentCompact", "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, err := os.ReadFile(childBoot)
			require.NoError(t, err)
			boot := filepath.Join(env.WorkDir(t), "image.boot")
			require.NoError(t, os.WriteFile(boot, original, 0600))
			export := boot
			if !tc.compact {
				export = filepath.Join(env.WorkDir(t), "export.boot")
			}
			repo := "artifact"
			if tc.compact {
				repo = "repacked-artifact"
			}
			ref := reg.Ref(repo, strings.ToLower(tc.name))
			start := len(reg.Faults.Requests())
			nydusify(t, "convert", "--bootstrap", boot, "--blob-dir", childDir, "--parent-image", parentRef,
				"--compact-max-layers", tc.limit, "--output-bootstrap", export, "--target", ref)
			fetched := false
			for _, request := range reg.Faults.Requests()[start:] {
				if request.Method == http.MethodGet && request.Path == "/v2/artifact/blobs/"+parent.Layers[0].Digest.String() {
					fetched = true
					require.Regexp(t, `^bytes=[0-9]+-[0-9]+$`, request.Range, "%+v", request)
				}
			}
			require.Equal(t, tc.compact, fetched, "only compaction should read parent data")
			published := remoteImage(t, ref)
			manifest, err := published.Manifest()
			require.NoError(t, err)
			layers := 3
			if tc.compact {
				layers = 2
			}
			require.Len(t, manifest.Layers, layers)
			final, err := os.ReadFile(export)
			require.NoError(t, err)
			require.Equal(t, bootstrapEntries(t, published)[bootstrapInLayer], final)
			if tc.compact {
				require.NotEqual(t, original, final)
			} else {
				require.Equal(t, original, final)
			}
			mounted := mount.Mount(t, mount.FUSE{}, pullNydus(t, ref, nil), mount.Options{})
			for name, want := range map[string]string{"changed": "child changed\n", "created": "child created\n", "unchanged": unchanged} {
				got, err := os.ReadFile(mounted.Path(name))
				require.NoError(t, err)
				require.Equal(t, want, string(got), name)
			}
		})
	}
	t.Run("ExportFailureAfterPush", func(t *testing.T) {
		blocked := env.WorkDir(t)
		ref := reg.Ref("artifact", "export-failure")
		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--parent-image", parentRef, "--output-bootstrap", blocked, "--target", ref)
		require.Error(t, err, "%s", out)
		require.Contains(t, out, "save published bootstrap")
		manifest, err := remoteImage(t, ref).Manifest()
		require.NoError(t, err, "the image was published before local export failed")
		require.Len(t, manifest.Layers, 3)
		entries, err := os.ReadDir(blocked)
		require.NoError(t, err)
		require.Empty(t, entries, "failed export must not leave temporary files")
	})
	t.Run("ParentPublicationFailure", func(t *testing.T) {
		export := filepath.Join(env.WorkDir(t), "image.boot")
		require.NoError(t, os.WriteFile(export, []byte("retained bootstrap"), 0600))
		start := len(reg.Faults.Requests())
		reg.Faults.Set(
			registry.Fault{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
				return r.Method == http.MethodHead && r.URL.Path == "/v2/rejected-artifact/blobs/"+parent.Layers[0].Digest.String()
			}},
			registry.Fault{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
				return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v2/rejected-artifact/blobs/uploads")
			}},
		)
		defer reg.Faults.Clear()
		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--parent-image", parentRef, "--output-bootstrap", export, "--target", reg.Ref("rejected-artifact", "child"))
		require.Error(t, err, "%s", out)
		require.Contains(t, out, "make parent blob")
		data, err := os.ReadFile(export)
		require.NoError(t, err)
		require.Equal(t, "retained bootstrap", string(data))
		for _, request := range reg.Faults.Requests()[start:] {
			require.False(t, request.Method == http.MethodPut && strings.HasPrefix(request.Path, "/v2/rejected-artifact/manifests/"), "manifest published after parent upload failure")
		}
	})
	for _, phase := range []string{"LocalBlobUploadFailure", "ManifestPublicationFailure", "ParentMetadataPullFailure"} {
		t.Run(phase, func(t *testing.T) {
			export := filepath.Join(env.WorkDir(t), "image.boot")
			require.NoError(t, os.WriteFile(export, []byte("retained bootstrap"), 0600))
			ref := reg.Ref("artifact", phase)
			want := ""
			switch phase {
			case "LocalBlobUploadFailure":
				want = "push local artifact blob"
				reg.Faults.Set(
					registry.Fault{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
						return r.Method == http.MethodHead && r.URL.Path == "/v2/artifact/blobs/"+child.Layers[1].Digest.String()
					}},
					registry.Fault{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
						return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v2/artifact/blobs/uploads")
					}},
				)
			case "ManifestPublicationFailure":
				want = "push "
				reg.Faults.Set(registry.Fault{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
					return r.Method == http.MethodPut && r.URL.Path == "/v2/artifact/manifests/"+phase
				}})
			case "ParentMetadataPullFailure":
				want = "pull parent metadata"
				reg.Faults.Set(registry.Fault{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
					return r.URL.Path == "/v2/artifact/manifests/parent"
				}})
			}
			defer reg.Faults.Clear()
			out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
				"--parent-image", parentRef, "--output-bootstrap", export, "--target", ref)
			require.Error(t, err, "%s", out)
			require.Contains(t, out, want)
			data, err := os.ReadFile(export)
			require.NoError(t, err)
			require.Equal(t, "retained bootstrap", string(data), "failed publishing must not replace the local bootstrap")
		})
	}
	t.Run("MissingParentBlob", func(t *testing.T) {
		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--target", reg.Ref("artifact", "missing"))
		require.Error(t, err, "%s", out)
		require.Contains(t, out, "missing nydus blob")
	})
}
