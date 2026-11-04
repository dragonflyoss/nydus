package nydusify

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestConvert(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)

	for _, src := range corpusSources(t) {
		srcRef := reg.Ref("convert-"+src.name, "oci")
		reg.PushDirs(t, srcRef, src.dirs...)

		for _, compressor := range []string{"zstd", "lz4", "none", "erofs-none", "erofs-lz4", "erofs-zstd"} {
			t.Run(src.name+"/"+compressor, func(t *testing.T) {
				t.Parallel()
				target := reg.Ref("convert-"+src.name, compressor)
				nydusify(t, "convert", "--source", srcRef, "--target", target, "--compressor", compressor)

				img := ref(target).pull(t, src.want)
				if !assert.Len(t, img.Blobs, len(src.dirs)) {
					t.FailNow()
				}

				m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				fstest.VerifyMount(t, m.Root, src.want, src.compare())
			})
		}
	}
}

func TestConvertIndex(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"shared": "same layer across architectures\n"})
	base := reg.PushDirs(t, reg.Ref("index", "seed"), src)
	var index v1.ImageIndex = empty.Index

	for _, arch := range []string{"amd64", "arm64"} {
		cfg, err := base.ConfigFile()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		cfg = cfg.DeepCopy()
		cfg.Architecture = arch
		cfg.Config.Env = []string{"ARCH=" + arch}
		image, err := mutate.ConfigFile(base, cfg)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}

	source := reg.Ref("index", "source")
	sourceRef := ref(source).parse(t)
	if !assert.NoError(t, remote.WriteIndex(sourceRef, index)) {
		t.FailNow()
	}

	for _, filter := range []string{"all", "arm64"} {
		t.Run(filter, func(t *testing.T) {
			t.Parallel()
			target := reg.Ref("index", filter)

			args := []string{"convert", "--source", source, "--target", target}
			if filter != "all" {
				args = append(args, "--platform", "linux/"+filter)
			}

			nydusify(t, args...)
			targetRef := ref(target).parse(t)
			root, err := remote.Get(targetRef)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			var children []v1.Descriptor
			if filter == "all" {
				if !assert.True(t, root.MediaType.IsIndex()) {
					t.FailNow()
				}

				converted, err := root.ImageIndex()
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				manifest, err := converted.IndexManifest()
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Len(t, manifest.Manifests, 2) {
					t.FailNow()
				}

				children = manifest.Manifests
			} else {
				if !assert.True(t, root.MediaType.IsImage()) {
					t.FailNow()
				}

				child := root.Descriptor
				child.Platform = &v1.Platform{OS: "linux", Architecture: filter}
				children = []v1.Descriptor{child}
			}

			var sharedBlob v1.Hash

			for _, desc := range children {
				if !assert.NotNil(t, desc.Platform) {
					t.FailNow()
				}

				childRef := targetRef.Context().Digest(desc.Digest.String()).String()
				image := ref(childRef).image(t)
				cfg, err := image.ConfigFile()
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Equal(t, desc.Platform.Architecture, cfg.Architecture) {
					t.FailNow()
				}

				assert.Equal(t, []string{"ARCH=" + cfg.Architecture}, cfg.Config.Env)
				child, err := image.Manifest()
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Len(t, child.Layers, 2) {
					t.FailNow()
				}
				if sharedBlob.Hex != "" {
					assert.Equal(t, sharedBlob, child.Layers[0].Digest)
				}

				sharedBlob = child.Layers[0].Digest
				img := ref(childRef).pull(t, fstest.ScanSource(t, src))
				m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
				m.Unmount()
			}

			reused := reg.Ref("index", filter+"-reused")
			nydusify(t, "convert", "--source", target, "--target", reused)
			reusedRef := ref(reused).parse(t)
			got, err := remote.Head(reusedRef)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			want, err := remote.Head(targetRef)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, want.Digest, got.Digest)
		})
	}
}

func TestConvertArtifact(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	writer := env.Writer(t)
	reg := registry.Start(t)
	unchanged := strings.Repeat("parent unchanged\n", 8192)
	src := inputTree(t, map[string]string{"changed": strings.Repeat("parent changed\n", 4096), "unchanged": unchanged})
	dir := env.WorkDir(t)
	parentBoot, parentBlobs := filepath.Join(dir, "parent.boot"), filepath.Join(dir, "parent-blobs")
	layout := fixture.MustLayout(t, "zstd")
	parentBlob, _ := fixture.BuildInto(t, parentBlobs, parentBoot, src, layout)
	parentRef, childRef := reg.Ref("artifact", "parent"), reg.Ref("artifact", "child")

	nydusify(t, "convert", "--bootstrap", parentBoot, "--blob-dir", parentBlobs, "--target", parentRef,
		"--manifest-annotation", "org.example.parent=inherited")

	parent, err := ref(parentRef).image(t).Manifest()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Len(t, parent.Layers, 2) {
		t.FailNow()
	}

	childDir := filepath.Join(dir, "child")
	env.Run(t, writer, "--bootstrap", parentBoot, "--blob-dir", parentBlobs, "--output-dir", childDir)
	childBoot := filepath.Join(childDir, "image.boot")

	parentBlobGet := func(r registry.Request) bool {
		return r.Method == http.MethodGet && r.Path == "/v2/artifact/blobs/"+parent.Layers[0].Digest.String()
	}

	before := reg.Faults.Count(parentBlobGet)

	nydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir, "--parent-image", parentRef,
		"--target", childRef, "--manifest-annotation", "org.example.child=new")

	assert.Equal(t, before, reg.Faults.Count(parentBlobGet))

	child, err := ref(childRef).image(t).Manifest()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Len(t, child.Layers, 3) {
		t.FailNow()
	}
	if !assert.Equal(t, parent.Layers[0], child.Layers[0]) {
		t.FailNow()
	}
	if !assert.Equal(t, "inherited", child.Annotations["org.example.parent"]) {
		t.FailNow()
	}
	if !assert.Equal(t, "new", child.Annotations["org.example.child"]) {
		t.FailNow()
	}

	entries := bootstrapEntries(t, ref(childRef).image(t))
	if !assert.Contains(t, entries, "image/"+parent.Layers[0].Digest.Hex+".blob.meta") {
		t.FailNow()
	}
	if !assert.Contains(t, entries, "image/"+child.Layers[1].Digest.Hex+".blob.meta") {
		t.FailNow()
	}

	img := ref(childRef).pull(t, nil)
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	names, err := os.ReadDir(m.Root)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Len(t, names, 3)

	expectChild := func(t *testing.T, root string) {
		t.Helper()
		for name, want := range map[string]string{"changed": "child changed\n", "created": "child created\n", "unchanged": unchanged} {
			data, err := os.ReadFile(filepath.Join(root, name))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, want, string(data))
		}
	}

	expectChild(t, m.Root)

	t.Run("CrossRepositoryParent", func(t *testing.T) {
		crossRef := reg.Ref("other-artifact", "child")

		nydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--parent-image", parentRef, "--target", crossRef)

		cross, err := ref(crossRef).image(t).Manifest()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Len(t, cross.Layers, 3) {
			t.FailNow()
		}

		assert.Equal(t, parent.Layers[0], cross.Layers[0])
		crossImage := ref(crossRef).pull(t, nil)
		expectChild(t, mount.Mount(t, mount.FUSE{}, crossImage, mount.Options{}).Root)
	})

	t.Run("PruneUnusedDevice", func(t *testing.T) {
		work := env.WorkDir(t)
		obsolete := inputTree(t, map[string]string{"changed": "obsolete changed", "unchanged": "obsolete unchanged"})
		deadBlob, _ := fixture.BuildInto(t, filepath.Join(work, "dead-blobs"), filepath.Join(work, "dead.boot"), obsolete, layout)
		boot := filepath.Join(work, "image.boot")
		env.Run(t, env.Nydus(t), "merge", deadBlob, parentBlob, "--bootstrap", boot)

		original, err := os.ReadFile(boot)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		prunedRef := reg.Ref("artifact", "pruned")

		nydusify(t, "convert", "--bootstrap", boot, "--blob", parentBlob, "--prune",
			"--output-bootstrap", boot, "--target", prunedRef)

		published := ref(prunedRef).image(t)
		manifest, err := published.Manifest()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Len(t, manifest.Layers, 2) {
			t.FailNow()
		}

		assert.Equal(t, parent.Layers[0].Digest, manifest.Layers[0].Digest)
		final, err := os.ReadFile(boot)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.False(t, bytes.Equal(original, final))
		assert.True(t, bytes.Equal(bootstrapEntries(t, published)[bootstrapInLayer], final))
		pruned := mount.Mount(t, mount.FUSE{}, ref(prunedRef).pull(t, nil), mount.Options{})

		for _, name := range []string{"changed", "unchanged"} {
			want, err := os.ReadFile(filepath.Join(src, name))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			got, err := os.ReadFile(pruned.Path(name))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.True(t, bytes.Equal(want, got))
		}
	})

	for _, tc := range []struct {
		name    string
		repo    string
		limit   string
		compact bool
		layers  int
	}{
		{"ExportWithoutCompact", "artifact", "2", false, 3},
		{"RemoteParentCompact", "repacked-artifact", "1", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, err := os.ReadFile(childBoot)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			work := env.WorkDir(t)
			boot := filepath.Join(work, "image.boot")
			if !assert.NoError(t, os.WriteFile(boot, original, 0o600)) {
				t.FailNow()
			}

			export := boot
			if !tc.compact {
				export = filepath.Join(work, "export.boot")
			}

			target := reg.Ref(tc.repo, strings.ToLower(tc.name))
			start := len(reg.Faults.Requests())

			nydusify(t, "convert", "--bootstrap", boot, "--blob-dir", childDir, "--parent-image", parentRef,
				"--compact-max-layers", tc.limit, "--output-bootstrap", export, "--target", target)

			var parentReads []registry.Request

			for _, r := range reg.Faults.Requests()[start:] {
				if parentBlobGet(r) {
					parentReads = append(parentReads, r)
				}
			}

			assert.Equal(t, tc.compact, len(parentReads) > 0)

			for _, r := range parentReads {
				assert.Regexp(t, `^bytes=[0-9]+-[0-9]+$`, r.Range)
			}

			published := ref(target).image(t)
			manifest, err := published.Manifest()
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Len(t, manifest.Layers, tc.layers) {
				t.FailNow()
			}

			final, err := os.ReadFile(export)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.True(t, bytes.Equal(bootstrapEntries(t, published)[bootstrapInLayer], final))
			assert.Equal(t, !tc.compact, bytes.Equal(original, final))
			expectChild(t, mount.Mount(t, mount.FUSE{}, ref(target).pull(t, nil), mount.Options{}).Root)
		})
	}

	t.Run("ExportFailureAfterPush", func(t *testing.T) {
		blocked := env.WorkDir(t)
		target := reg.Ref("artifact", "export-failure")

		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--parent-image", parentRef, "--output-bootstrap", blocked, "--target", target)

		if !assert.Error(t, err) {
			t.FailNow()
		}

		assert.Contains(t, out, "save published bootstrap")
		manifest, err := ref(target).image(t).Manifest()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Len(t, manifest.Layers, 3)
		entries, err := os.ReadDir(blocked)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Empty(t, entries)
	})

	for _, tc := range []struct {
		name   string
		repo   string
		want   string
		faults []registry.Fault
	}{
		{"ParentPublicationFailure", "rejected-artifact", "make parent blob", []registry.Fault{
			{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
				return r.Method == http.MethodHead && r.URL.Path == "/v2/rejected-artifact/blobs/"+parent.Layers[0].Digest.String()
			}},
			{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
				return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v2/rejected-artifact/blobs/uploads")
			}},
		}},
		{"LocalBlobUploadFailure", "artifact", "push local artifact blob", []registry.Fault{
			{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
				return r.Method == http.MethodHead && r.URL.Path == "/v2/artifact/blobs/"+child.Layers[1].Digest.String()
			}},
			{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
				return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v2/artifact/blobs/uploads")
			}},
		}},
		{"ManifestPublicationFailure", "artifact", "push ", []registry.Fault{
			{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
				return r.Method == http.MethodPut && r.URL.Path == "/v2/artifact/manifests/ManifestPublicationFailure"
			}},
		}},
		{"ParentMetadataPullFailure", "artifact", "pull parent metadata", []registry.Fault{
			{Status: http.StatusNotFound, Match: func(r *http.Request) bool {
				return r.URL.Path == "/v2/artifact/manifests/parent"
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			export := filepath.Join(env.WorkDir(t), "image.boot")
			if !assert.NoError(t, os.WriteFile(export, []byte("retained bootstrap"), 0o600)) {
				t.FailNow()
			}

			target := reg.Ref(tc.repo, tc.name)
			reg.Faults.Set(tc.faults...)
			t.Cleanup(reg.Faults.Clear)

			out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
				"--parent-image", parentRef, "--output-bootstrap", export, "--target", target)

			if !assert.Error(t, err) {
				t.FailNow()
			}

			assert.Contains(t, out, tc.want)
			data, err := os.ReadFile(export)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, "retained bootstrap", string(data))
			ref(target).expectAbsent(t)
		})
	}

	t.Run("MissingParentBlob", func(t *testing.T) {
		out, err := tryNydusify(t, "convert", "--bootstrap", childBoot, "--blob-dir", childDir,
			"--target", reg.Ref("artifact", "missing"))

		if !assert.Error(t, err) {
			t.FailNow()
		}

		assert.Contains(t, out, "missing nydus blob")
	})
}

func TestConvertInputs(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)

	t.Run("LocalDirectory", func(t *testing.T) {
		t.Parallel()
		src := inputTree(t, map[string]string{"keep": "kept\n", "bundle": "bootstrap only\n"})
		target := reg.Ref("local", "nydus")

		nydusify(t, "convert", "--source", src, "--target", target,
			"--append-in-bootstrap", filepath.Join(src, "bundle"), "--manifest-annotation", "org.example.test=local")

		remoteImg := ref(target).image(t)
		manifest, err := remoteImg.Manifest()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, "local", manifest.Annotations["org.example.test"])
		assert.Equal(t, []byte("bootstrap only\n"), bootstrapEntries(t, remoteImg)["image/bundle"])
		want := slices.DeleteFunc(fstest.ScanSource(t, src), func(e fstest.Entry) bool { return string(e.Path) == "bundle" })
		img := ref(target).pull(t, want)
		if !assert.Len(t, img.Blobs, 1) {
			t.FailNow()
		}

		m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
		fstest.VerifyMount(t, m.Root, want, fstest.CompareOptions{Nlink: true})
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
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		cfg = cfg.DeepCopy()
		cfg.Config.Env = []string{"SOURCE=upper"}
		cfg.Config.Entrypoint = []string{"/upper"}
		image, err = mutate.ConfigFile(image, cfg)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		parsed := ref(upperOCI).parse(t)
		assert.NoError(t, remote.Write(parsed, image))
		upperRef := reg.Ref("mixed", "upper-nydus")
		nydusify(t, "convert", "--source", upperOCI, "--target", upperRef)
		target := reg.Ref("mixed", "result")

		nydusify(t, "convert", "--source", base, "--source", middleRef, "--source", upperRef,
			"--source", top, "--target", target, "--manifest-annotation", "org.example.test=mixed")

		want := newSource(t, "mixed", base, middle, upper, top)
		img := ref(target).pull(t, want.want)
		if !assert.Len(t, img.Blobs, 4) {
			t.FailNow()
		}

		m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
		fstest.VerifyMount(t, m.Root, want.want, want.compare())
		result := ref(target).image(t)
		got, err := result.ConfigFile()
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, cfg.Config.Env, got.Config.Env) {
			t.FailNow()
		}

		assert.Equal(t, cfg.Config.Entrypoint, got.Config.Entrypoint)
		manifest, err := result.Manifest()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, "mixed", manifest.Annotations["org.example.test"])
	})
}

func TestConvertCancel(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"payload": "cancel and resume\n"})
	source, target := reg.Ref("cancel", "source"), reg.Ref("cancel", "target")
	reg.PushDirs(t, source, src)

	reg.Faults.Set(registry.Fault{Delay: time.Minute})

	work := t.TempDir()
	dir := env.WorkDir(t)
	args := []string{"convert", "--source", source, "--target", target, "--work-dir", work}

	d := mount.StartDaemon(t, dir, "nydusify-convert", env.Nydusify(t),
		append(args, "--builder", env.Nydus(t), "--source-plain-http", "--target-plain-http")...)

	d.WaitFor(t, 10*time.Second, "blocked registry read", func() bool { return reg.Faults.Hits() > 0 })
	d.Signal(unix.SIGTERM)

	if !assert.True(t, d.WaitExit(10*time.Second)) {
		t.FailNow()
	}

	assert.Positive(t, d.ExitCode())
	ref(target).expectAbsent(t)
	reg.Faults.Clear()
	nydusify(t, args...)
	img := ref(target).pull(t, fstest.ScanSource(t, src))
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
}

func TestPublishRecovery(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	for _, stage := range []string{"blob", "manifest", "eager"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			reg := registry.Start(t)
			src := inputTree(t, map[string]string{"payload": strings.Repeat("publish recovery\n", 8192)})
			source, target := reg.Ref("source", "oci"), reg.Ref("target", "nydus")
			reg.PushDirs(t, source, src)

			times := 0
			if stage == "eager" {
				times = 1
			}

			reg.Faults.Set(registry.Fault{Status: http.StatusForbidden, Times: times, Match: func(r *http.Request) bool {
				if !strings.HasPrefix(r.URL.Path, "/v2/target/") {
					return false
				}
				if stage != "manifest" {
					return r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/")
				}

				return r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/")
			}})

			work := t.TempDir()
			args := []string{"convert", "--source", source, "--target", target, "--work-dir", work}
			out, err := tryNydusify(t, args...)

			if !assert.Positive(t, reg.Faults.Hits()) {
				t.FailNow()
			}

			if stage == "eager" {
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Contains(t, out, "eager blob push")
			} else {
				if !assert.Error(t, err) {
					t.FailNow()
				}

				ref(target).expectAbsent(t)
				reg.Faults.Clear()
				nydusify(t, args...)
			}

			img := ref(target).pull(t, fstest.ScanSource(t, src))
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
			fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	}
}

func TestToOCI(t *testing.T) {
	t.Parallel()
	env.MustHaveRoot(t)
	reg := registry.Start(t)

	srcs := []source{
		newSource(t, "files", makeToOCILayers(t, env.WorkDir(t))...),
		newSource(t, "whiteouts", fixture.LayerDirs(t)...),
	}

	for _, src := range srcs {
		t.Run(src.name, func(t *testing.T) {
			t.Parallel()
			srcRef := reg.Ref("tooci-"+src.name, "oci")
			nydusRef := reg.Ref("tooci-"+src.name, "nydus")
			reg.PushDirs(t, srcRef, src.dirs...)
			nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)
			nydusify(t, "check", "--source", srcRef, "--target", nydusRef)

			for _, compressor := range []string{"oci-gzip", "oci-zstd", "oci-tar"} {
				t.Run(compressor, func(t *testing.T) {
					t.Parallel()
					ociRef := reg.Ref("tooci-"+src.name, compressor)
					nydusify(t, "convert", "--compressor", compressor, "--source", nydusRef, "--target", ociRef)
					nydusify(t, "check", "--source", nydusRef, "--target", ociRef)

					img := ref(ociRef).image(t)
					manifest, err := img.Manifest()
					if !assert.NoError(t, err) {
						t.FailNow()
					}
					if !assert.Len(t, manifest.Layers, len(src.dirs)) {
						t.FailNow()
					}

					for _, layer := range manifest.Layers {
						if !assert.Equal(t, layerMediaType(compressor), string(layer.MediaType)) {
							t.FailNow()
						}

						for key := range layer.Annotations {
							assert.NotContains(t, key, "nydus")
						}
					}

					config, err := img.ConfigFile()
					if !assert.NoError(t, err) {
						t.FailNow()
					}
					if !assert.Len(t, config.RootFS.DiffIDs, len(src.dirs)) {
						t.FailNow()
					}

					for _, entry := range config.History {
						assert.NotContains(t, entry.Comment, "Nydus")
					}

					fstest.VerifyMount(t, ref(ociRef).extract(t), src.want, src.compare())
				})
			}
		})
	}
}

func layerMediaType(compressor string) string {
	switch compressor {
	case "oci-zstd":
		return ocispec.MediaTypeImageLayerZstd

	case "oci-tar":
		return ocispec.MediaTypeImageLayer

	default:
		return ocispec.MediaTypeImageLayerGzip
	}
}

func makeToOCILayers(t *testing.T, dir string) []string {
	t.Helper()
	dirs := []string{filepath.Join(dir, "lower"), filepath.Join(dir, "middle"), filepath.Join(dir, "upper")}

	base := corpus.New(t, dirs[0])
	base.CreateFile(t, "files/empty", nil)
	base.CreateFile(t, "files/tiny", []byte("hi"))
	base.CreateFile(t, "files/just_under_block", []byte(strings.Repeat("A", 4095)))
	base.CreateRandomFile(t, "files/exact_block", 4096)
	base.CreateRandomFile(t, "files/one_over_block", 4097)
	base.CreateRandomFile(t, "files/large_256k", 256*1024)
	base.CreateZeroFile(t, "files/all_zeros", 4096*4)
	base.CreateFile(t, "files/overridden", []byte("from layer1"))
	base.CreateDir(t, "dirs/empty_dir")
	base.CreateDir(t, "dirs/a/b/c/d/e/f")
	base.CreateFile(t, "dirs/a/b/c/d/e/f/deep_file", []byte("deep"))

	for name, mode := range map[string]uint32{"r_only": 0o444, "setuid": 0o4755, "setgid": 0o2755, "sticky": 0o1755} {
		base.CreateFile(t, "perms/"+name, []byte(name))
		base.Chmod(t, "perms/"+name, mode)
	}

	links := corpus.New(t, dirs[1])
	links.CreateFile(t, "symlinks/target_file", []byte("target"))
	links.CreateSymlink(t, "symlinks/link_to_file", "target_file")
	links.CreateSymlink(t, "symlinks/relative_link", "../files/tiny")
	links.CreateSymlink(t, "symlinks/dangling", "nonexistent_target")
	longName := strings.Repeat("x", 200)
	links.CreateFile(t, "symlinks/"+longName, []byte("long"))
	links.CreateSymlink(t, "symlinks/link_to_long_name", longName)

	for _, n := range []int{99, 100, 101, 255, 1024, 4095} {
		links.CreateSymlink(t, fmt.Sprintf("symlinks/long_target_%04d", n), strings.Repeat("t", n))
	}

	links.CreateFile(t, "hardlinks/original", []byte("shared content"))
	links.CreateHardlink(t, "hardlinks/link1", "hardlinks/original")
	links.CreateDir(t, "hardlinks/subdir")
	links.CreateHardlink(t, "hardlinks/subdir/link2", "hardlinks/original")

	top := corpus.New(t, dirs[2])
	top.CreateFile(t, "files/overridden", []byte("from layer3"))
	top.CreateDir(t, "dirs/many_entries")

	for i := 1; i <= 200; i++ {
		top.CreateFile(t, fmt.Sprintf("dirs/many_entries/file_%04d", i), fmt.Appendf(nil, "entry_%d", i))
	}

	return dirs
}
