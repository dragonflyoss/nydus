package pipeline

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type testBlobReader struct{ *bytes.Reader }
type countedBlobReader struct {
	io.ReadSeekCloser
	bytes *atomic.Int64
}

func (r countedBlobReader) Read(b []byte) (int, error) {
	n, err := r.ReadSeekCloser.Read(b)
	r.bytes.Add(int64(n))
	return n, err
}

func (testBlobReader) Close() error { return nil }

func TestRepackPreparationProtocol(t *testing.T) {
	id := digest.FromString("live").Encoded()
	plan := repackReport{Version: 1, Phase: "plan", Pruned: true, Blobs: []string{id}}
	result := plan
	result.Phase = "result"
	for _, tc := range []struct {
		name         string
		plan, result repackReport
		failPrepare  bool
		wantError    bool
	}{
		{"valid", plan, result, false, false},
		{"prepare failure", plan, result, true, true},
		{"bad version", repackReport{Version: 2, Phase: "plan"}, result, false, true},
		{"bad phase", result, result, false, true},
		{"invalid digest", repackReport{Version: 1, Phase: "plan", Blobs: []string{"invalid"}}, result, false, true},
		{"duplicate digest", repackReport{Version: 1, Phase: "plan", Blobs: []string{id, id}}, result, false, true},
		{"changed decision", plan, repackReport{Version: 1, Phase: "result", Compacted: true}, false, true},
		{"changed references", plan, repackReport{Version: 1, Phase: "result", Pruned: true}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			builder := filepath.Join(dir, "builder")
			p, err := json.Marshal(tc.plan)
			require.NoError(t, err)
			r, err := json.Marshal(tc.result)
			require.NoError(t, err)
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\nread -r ready || exit 7\n[ \"$ready\" = ready ] || exit 8\nprintf '%%s\\n' '%s'\n", p, r)
			require.NoError(t, os.WriteFile(builder, []byte(script), 0700))
			prepared := false
			got, err := executeArtifactRepack(context.Background(), ArtifactOption{BuilderPath: builder}, dir, dir, func(report repackReport) error {
				prepared = true
				require.Equal(t, plan.Blobs, report.Blobs)
				if tc.failPrepare {
					return context.Canceled
				}
				return nil
			})
			if tc.wantError {
				require.Error(t, err)
				if tc.failPrepare {
					require.ErrorIs(t, err, context.Canceled)
				}
			} else {
				require.NoError(t, err)
				require.True(t, prepared)
				require.Equal(t, result, got)
			}
		})
	}
}

func TestRepackChildFailures(t *testing.T) {
	id := digest.FromString("live").Encoded()
	plan := fmt.Sprintf(`{"version":1,"phase":"plan","blobs":[%q]}`, id)
	result := fmt.Sprintf(`{"version":1,"phase":"result","blobs":[%q]}`, id)
	for _, tc := range []struct{ name, script, expected string }{
		{"missing builder", "", "no such file"},
		{"invalid plan", "printf 'invalid'", "read repack plan"},
		{"closed input", "exec 0<&-; printf '%s\\n' '" + plan + "'; exec sleep 10", "broken pipe"},
		{"invalid result", "printf '%s\\n' '" + plan + "'; read -r ready; printf 'invalid'", "read repack result"},
		{"failed child", "printf '%s\\n' '" + plan + "'; read -r ready; printf '%s\\n' '" + result + "'; exit 7", "exit status 7"},
		{"invalid result digest", "printf '%s\\n' '" + plan + "'; read -r ready; printf '%s\\n' '{\"version\":1,\"phase\":\"result\",\"blobs\":[\"invalid\"]}'", "invalid repack blob digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := filepath.Join(t.TempDir(), "builder")
			if tc.script != "" {
				require.NoError(t, os.WriteFile(builder, []byte("#!/bin/sh\n"+tc.script+"\n"), 0700))
			}
			_, err := executeArtifactRepack(context.Background(), ArtifactOption{BuilderPath: builder}, t.TempDir(), t.TempDir(), func(repackReport) error { return nil })
			require.ErrorContains(t, err, tc.expected)
		})
	}
}

func TestRepackPipeExhaustion(t *testing.T) {
	mode := os.Getenv("NYDUS_TEST_REPACK_FD_LIMIT")
	if mode == "" {
		for _, mode := range []string{"stdout", "stdin", "backend"} {
			t.Run(mode, func(t *testing.T) {
				// Keep process-wide resource limits isolated from the test runner.
				cmd := exec.Command(os.Args[0], "-test.run=^TestRepackPipeExhaustion$")
				if cover := flag.Lookup("test.gocoverdir"); cover != nil && cover.Value.String() != "" {
					cmd.Args = append(cmd.Args, "-test.gocoverdir="+cover.Value.String())
				}
				cmd.Env = append(os.Environ(), "NYDUS_TEST_REPACK_FD_LIMIT="+mode)
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", out)
			})
		}
		return
	}
	dir := t.TempDir()
	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))
	bounded := limit
	bounded.Cur = min(limit.Cur, 64)
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &bounded))
	var files []*os.File
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
		require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit))
	}()
	for {
		file, err := os.Open("/dev/null")
		if err != nil {
			require.ErrorIs(t, err, syscall.EMFILE)
			break
		}
		files = append(files, file)
	}
	if mode == "stdin" {
		// Leave room for StdoutPipe, but not for a second pipe.
		require.GreaterOrEqual(t, len(files), 2)
		for range 2 {
			last := len(files) - 1
			require.NoError(t, files[last].Close())
			files = files[:last]
		}
	}
	if mode == "backend" {
		_, _, err := repackArtifact(context.Background(), ArtifactOption{
			WorkDir:          dir,
			CompactMaxLayers: 1,
			ParentImages:     []ParentImageMetadata{{}},
			OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
				t.Fatal("backend startup failure must not fetch parent data")
				return nil, nil
			},
		}, 2, func(repackReport, string) error {
			t.Fatal("backend startup failure must not prepare blobs")
			return nil
		})
		require.ErrorIs(t, err, syscall.EMFILE)
		return
	}
	_, err := executeArtifactRepack(context.Background(), ArtifactOption{BuilderPath: "/bin/true"}, dir, dir, func(repackReport) error { return nil })
	require.ErrorIs(t, err, syscall.EMFILE)
}

func TestRepackRejectsReadOnlyWorkFilesystem(t *testing.T) {
	// /proc/self exists but cannot hold repack temporary directories, even as root.
	_, _, err := repackArtifact(context.Background(), ArtifactOption{WorkDir: "/proc/self"}, 0, func(repackReport, string) error { return nil })
	require.Error(t, err)
}

func TestRepackValidationAndStagingFailures(t *testing.T) {
	for _, tc := range []ArtifactOption{
		{CompactCompressor: "invalid", WorkDir: t.TempDir()},
		{},
		{WorkDir: filepath.Join(t.TempDir(), "file")},
	} {
		if strings.HasSuffix(tc.WorkDir, "/file") {
			require.NoError(t, os.WriteFile(tc.WorkDir, nil, 0600))
		}
		_, _, err := repackArtifact(context.Background(), tc, 0, func(repackReport, string) error { return nil })
		require.Error(t, err)
	}
	id := digest.FromString("blob")
	descs := []ocispec.Descriptor{{Digest: id}}
	for _, tc := range []string{"missing data", "duplicate destination", "blocked cache", "blocked metadata"} {
		t.Run(tc, func(t *testing.T) {
			work := t.TempDir()
			blobs := filepath.Join(work, "blobs")
			require.NoError(t, os.Mkdir(blobs, 0700))
			source := filepath.Join(work, "source")
			require.NoError(t, os.WriteFile(source, []byte("blob"), 0600))
			paths := map[digest.Digest]string{id: source}
			cache := filepath.Join(work, "output", "cache")
			meta := nydus.BlobMetaFile{Name: id.Encoded() + ".blob.meta", Data: []byte("meta")}
			switch tc {
			case "missing data":
				paths = nil
			case "duplicate destination":
				require.NoError(t, os.WriteFile(filepath.Join(blobs, id.Encoded()), nil, 0600))
			case "blocked cache":
				require.NoError(t, os.WriteFile(filepath.Join(work, "output"), nil, 0600))
			case "blocked metadata":
				require.NoError(t, os.MkdirAll(filepath.Join(cache, meta.Name), 0700))
			}
			require.Error(t, stageRepackBlobs(ArtifactOption{}, descs, paths, blobs, []nydus.BlobMetaFile{meta}))
			data, err := os.ReadFile(source)
			require.NoError(t, err)
			require.Equal(t, "blob", string(data))
		})
	}
}

func TestArtifactRepackRejectsInvalidOutputAndCleansWork(t *testing.T) {
	oldRun := runArtifactRepack
	defer func() { runArtifactRepack = oldRun }()
	for _, tc := range []string{"invalid references", "missing input", "missing metadata", "invalid local metadata", "conflicting input", "empty result", "missing result", "manifest failure"} {
		t.Run(tc, func(t *testing.T) {
			work := t.TempDir()
			boot := filepath.Join(work, "image.boot")
			require.NoError(t, os.WriteFile(boot, []byte("original"), 0600))
			id := digest.FromString("blob")
			opt := ArtifactOption{BootstrapPath: boot, WorkDir: filepath.Join(work, "scratch"), Prune: true}
			if tc == "missing metadata" || tc == "conflicting input" {
				opt.ParentImages = []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: id, Size: 4}}}}
			}
			if tc == "conflicting input" {
				path := filepath.Join(work, id.Encoded())
				require.NoError(t, os.WriteFile(path, []byte("different"), 0600))
				require.NoError(t, os.WriteFile(path+".blob.meta", []byte("meta"), 0600))
				opt.BlobPaths = []string{path}
			}
			if tc == "invalid local metadata" {
				path := filepath.Join(work, id.Encoded())
				require.NoError(t, os.WriteFile(path, []byte("blob"), 0600))
				opt.BlobPaths = []string{path}
			}
			runArtifactRepack = func(_ context.Context, _ ArtifactOption, _, output string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Compacted: true}
				if tc == "invalid references" {
					report.Blobs = []string{"invalid"}
				}
				if tc == "missing input" || tc == "missing metadata" || tc == "conflicting input" || tc == "invalid local metadata" {
					report.Blobs = []string{id.Encoded()}
				}
				if err := prepare(report); err != nil {
					return report, err
				}
				if tc == "missing result" {
					report.Blobs = []string{id.Encoded()}
				}
				if tc == "manifest failure" {
					report.Compacted = false
					report.Pruned = true
					require.NoError(t, os.MkdirAll(output, 0700))
					require.NoError(t, os.WriteFile(filepath.Join(output, "image.boot"), []byte("pruned"), 0600))
				}
				return report, nil
			}
			store, err := local.NewStore(filepath.Join(work, "content"))
			require.NoError(t, err)
			if tc == "manifest failure" {
				opt.ParentImages = []ParentImageMetadata{{Config: json.RawMessage(`invalid`)}}
			}
			_, err = ConvertNydusArtifacts(context.Background(), store, opt)
			require.Error(t, err)
			entries, err := os.ReadDir(opt.WorkDir)
			require.NoError(t, err)
			require.Empty(t, entries)
			data, err := os.ReadFile(boot)
			require.NoError(t, err)
			require.Equal(t, "original", string(data))
		})
	}
}

func TestArtifactMetadataValidationAndDeduplication(t *testing.T) {
	for _, output := range []string{"not json", `{"blobs":[{"slot_sha256":"invalid"}]}`} {
		builder := filepath.Join(t.TempDir(), "builder")
		require.NoError(t, os.WriteFile(builder, []byte("#!/bin/sh\nprintf '%s' '"+output+"'\n"), 0700))
		_, err := bootstrapBlobDigestsFromNydusCheck(context.Background(), builder, "image.boot")
		require.Error(t, err)
	}
	id := digest.FromString("data")
	desc := ocispec.Descriptor{Digest: id, Size: 4, MediaType: nydus.MediaTypeNydusBlob}
	metas := []nydus.BlobMetaFile{{Name: id.Encoded() + ".blob.meta", Data: []byte("metadata")}}
	_, _, external, localBlobs, err := deduplicateArtifactBlobs([]ocispec.Descriptor{desc, desc}, metas, []ocispec.Descriptor{desc, desc}, nil)
	require.NoError(t, err)
	require.Len(t, external, 1)
	require.Empty(t, localBlobs)
	_, _, _, localBlobs, err = deduplicateArtifactBlobs([]ocispec.Descriptor{desc, desc}, metas, nil, []LocalBlob{{Descriptor: desc}, {Descriptor: desc}})
	require.NoError(t, err)
	require.Len(t, localBlobs, 1)
	require.Error(t, validateArtifactBlobMetas([]ocispec.Descriptor{{Digest: digest.Digest("sha512:" + strings.Repeat("0", 128))}}, nil))
	_, ok := blobMetaDigest("image.boot")
	require.False(t, ok)
	path := filepath.Join(t.TempDir(), id.Encoded())
	require.NoError(t, os.WriteFile(path, []byte("data"), 0600))
	paths, err := collectArtifactBlobPaths([]string{"", path, path}, "")
	require.NoError(t, err)
	require.Equal(t, []string{path}, paths)
	_, _, err = describeArtifactBlob(path)
	require.Error(t, err)
}

func TestParentArtifactRejectsMissingMetadata(t *testing.T) {
	ctx := context.Background()
	store, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	bootstrap, err := oci.WriteBootstrapLayer(ctx, store, []byte("bootstrap"), nil, nil)
	require.NoError(t, err)
	id := digest.FromString("missing-metadata")
	manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Layers: []ocispec.Descriptor{
		{MediaType: nydus.MediaTypeNydusBlob, Digest: id, Size: 4, Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"}},
		*bootstrap,
	}}
	desc, err := oci.WriteJSON(ctx, store, manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	require.NoError(t, err)
	_, err = LoadParentNydusArtifact(ctx, store, *desc, platforms.All)
	require.ErrorContains(t, err, "missing blob meta")
}

func TestStageRemoteCompactDescriptorWriteFailure(t *testing.T) {
	blobs := t.TempDir()
	id := digest.FromString("remote")
	require.NoError(t, os.Mkdir(filepath.Join(blobs, id.Encoded()+".descriptor.json"), 0700))
	opt := ArtifactOption{OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
		t.Fatal("preparation must not fetch data")
		return nil, nil
	}}
	require.Error(t, stageRepackBlobs(opt, []ocispec.Descriptor{{Digest: id}}, nil, blobs, nil))
}

func TestArtifactPrunesWithoutFetchingBlobData(t *testing.T) {
	oldRun, oldInspect := runArtifactRepack, inspectBootstrapBlobDigests
	defer func() { runArtifactRepack, inspectBootstrapBlobDigests = oldRun, oldInspect }()
	inspectBootstrapBlobDigests = func(context.Context, string, string) (map[digest.Digest]struct{}, error) {
		t.Fatal("repack must not parse the bootstrap a second time")
		return nil, nil
	}
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprint(live), func(t *testing.T) {
			work := t.TempDir()
			bootstrap := filepath.Join(work, "image.boot")
			require.NoError(t, os.WriteFile(bootstrap, []byte("original"), 0600))
			id := digest.FromString("live")
			dead := digest.FromString("dead")
			runArtifactRepack = func(_ context.Context, _ ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Pruned: true}
				if live {
					report.Blobs = []string{id.Encoded()}
				}
				if err := prepare(report); err != nil {
					return report, err
				}
				entries, err := os.ReadDir(blobs)
				require.NoError(t, err)
				require.Empty(t, entries)
				require.NoError(t, os.MkdirAll(output, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(output, "image.boot"), []byte("pruned"), 0600))
				return report, nil
			}
			store, err := local.NewStore(filepath.Join(work, "content"))
			require.NoError(t, err)
			result, err := ConvertNydusArtifacts(context.Background(), store, ArtifactOption{
				BootstrapPath: bootstrap, WorkDir: work, Prune: true, CompactMaxLayers: 0,
				ParentImages: []ParentImageMetadata{{
					Blobs: []ocispec.Descriptor{
						{Digest: id, Size: 4, MediaType: nydus.MediaTypeNydusBlob, Annotations: map[string]string{nydus.LayerAnnotationUncompressed: id.String()}},
						{Digest: dead, Size: 4, MediaType: nydus.MediaTypeNydusBlob},
					},
					BlobMetas: []nydus.BlobMetaFile{
						{Name: id.Encoded() + ".blob.meta", Data: []byte("meta")},
						{Name: dead.Encoded() + ".blob.meta", Data: []byte("meta")},
					},
				}},
				OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
					t.Fatal("pure prune must not fetch blob data")
					return nil, nil
				},
			})
			require.NoError(t, err)
			require.True(t, result.Pruned)
			require.False(t, result.Compacted)
			data, err := os.ReadFile(result.BootstrapPath)
			require.NoError(t, err)
			require.Equal(t, []byte("pruned"), data)
			require.Empty(t, result.LocalBlobs)
			expected := 0
			if live {
				expected = 1
			}
			require.Len(t, result.ExternalBlobs, expected)
			data, err = os.ReadFile(bootstrap)
			require.NoError(t, err)
			require.Equal(t, "original", string(data))
		})
	}
}

func TestArtifactCompactsOnlyAboveDataLayerLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	bootstrap := filepath.Join(dir, "image.boot")
	require.NoError(t, os.WriteFile(bootstrap, []byte("original"), 0o600))
	upper := digest.FromString("upper")
	parent := digest.FromString("parent")
	unused := digest.FromString("unused-parent")
	merged := digest.FromString("merged")
	path := filepath.Join(dir, upper.Encoded())
	require.NoError(t, os.WriteFile(path, []byte("upper"), 0o600))
	require.NoError(t, os.WriteFile(path+".blob.meta", []byte("upper meta"), 0o600))
	oldInspect, oldRun := inspectBootstrapBlobDigests, runArtifactRepack
	defer func() { inspectBootstrapBlobDigests, runArtifactRepack = oldInspect, oldRun }()
	inspectBootstrapBlobDigests = func(_ context.Context, _, boot string) (map[digest.Digest]struct{}, error) {
		if boot == bootstrap {
			return map[digest.Digest]struct{}{upper: {}, parent: {}}, nil
		}
		return map[digest.Digest]struct{}{merged: {}}, nil
	}
	runs, downloads := 0, 0
	runArtifactRepack = func(_ context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error) {
		report := repackReport{Version: 1, Phase: "result", Blobs: []string{parent.Encoded(), upper.Encoded()}}
		report.Compacted = opt.CompactMaxLayers > 0 && uint(len(report.Blobs)) > opt.CompactMaxLayers
		require.NoError(t, prepare(report))
		if !report.Compacted {
			return report, nil
		}
		runs++
		require.Equal(t, bootstrap, opt.BootstrapPath)
		if _, err := os.Stat(filepath.Join(blobs, parent.Encoded())); os.IsNotExist(err) {
			require.FileExists(t, filepath.Join(blobs, parent.Encoded()+".descriptor.json"))
			reader, err := opt.OpenCompactBlob(context.Background(), ocispec.Descriptor{Digest: parent}, "bytes=0-0")
			require.NoError(t, err)
			require.NoError(t, reader.Close())
		}
		require.FileExists(t, filepath.Join(blobs, upper.Encoded()))
		require.NoError(t, os.MkdirAll(filepath.Join(output, "cache"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(output, "cache", "decoded.blob.data"), []byte("cache"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(output, "image.boot"), []byte("compacted"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(output, merged.Encoded()), []byte("merged"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(output, merged.Encoded()+".blob.meta"), []byte("merged meta"), 0600))
		report.Blobs = []string{merged.Encoded()}
		return report, nil
	}
	for _, limit := range []uint{0, 2, 1} {
		store, err := local.NewStore(filepath.Join(t.TempDir(), "content"))
		require.NoError(t, err)
		result, err := ConvertNydusArtifacts(ctx, store, ArtifactOption{
			BootstrapPath: bootstrap, BlobPaths: []string{path},
			WorkDir: dir, CompactMaxLayers: limit,
			ParentImages: []ParentImageMetadata{{
				Blobs: []ocispec.Descriptor{
					{Digest: parent, Size: 6, MediaType: nydus.MediaTypeNydusBlob, Annotations: map[string]string{nydus.LayerAnnotationUncompressed: parent.String()}},
					{Digest: unused, Size: 6, MediaType: nydus.MediaTypeNydusBlob, Annotations: map[string]string{nydus.LayerAnnotationUncompressed: unused.String()}},
				},
				BlobMetas: []nydus.BlobMetaFile{
					{Name: parent.Encoded() + ".blob.meta", Data: []byte("parent meta")},
					{Name: unused.Encoded() + ".blob.meta", Data: []byte("unused meta")},
				},
				Annotations: map[string]string{"org.example.snapshot": "retained"},
			}},
			OpenCompactBlob: func(_ context.Context, desc ocispec.Descriptor, _ string) (io.ReadSeekCloser, error) {
				downloads++
				require.Equal(t, parent, desc.Digest)
				return testBlobReader{bytes.NewReader([]byte("parent"))}, nil
			},
		})
		require.NoError(t, err)
		var manifest ocispec.Manifest
		require.NoError(t, oci.ReadJSON(ctx, store, *result.Descriptor, &manifest))
		require.Equal(t, "retained", manifest.Annotations["org.example.snapshot"])
		if limit == 1 {
			require.True(t, result.Compacted)
			data, err := os.ReadFile(result.BootstrapPath)
			require.NoError(t, err)
			require.Equal(t, []byte("compacted"), data)
			require.Len(t, manifest.Layers, 2)
			require.Equal(t, merged, manifest.Layers[0].Digest)
			require.Empty(t, result.ExternalBlobs)
			require.FileExists(t, result.LocalBlobs[0].Path)
			output := filepath.Dir(result.LocalBlobs[0].Path)
			require.NoDirExists(t, filepath.Join(output, "cache"))
			require.NoDirExists(t, filepath.Join(filepath.Dir(output), "blobs"))
		} else {
			require.False(t, result.Compacted)
			data, err := os.ReadFile(result.BootstrapPath)
			require.NoError(t, err)
			require.Equal(t, []byte("original"), data)
			require.Len(t, manifest.Layers, 3)
			require.Zero(t, downloads)
			require.Zero(t, runs)
		}
	}
	require.Equal(t, 1, downloads)
	require.Equal(t, 1, runs)

	// A parent descriptor may be external for upload purposes while its full
	// blob is also available locally. Compaction must use that local copy.
	parentPath := filepath.Join(dir, parent.Encoded())
	require.NoError(t, os.WriteFile(parentPath, []byte("parent"), 0o600))
	require.NoError(t, os.WriteFile(parentPath+".blob.meta", []byte("parent meta"), 0o600))
	store, err := local.NewStore(filepath.Join(t.TempDir(), "content"))
	require.NoError(t, err)
	result, err := ConvertNydusArtifacts(ctx, store, ArtifactOption{
		BootstrapPath: bootstrap, BlobDir: dir,
		WorkDir: dir, CompactMaxLayers: 1,
		ParentImages: []ParentImageMetadata{{
			Blobs:     []ocispec.Descriptor{{Digest: parent, Size: 6, MediaType: nydus.MediaTypeNydusBlob, Annotations: map[string]string{nydus.LayerAnnotationUncompressed: parent.String()}}},
			BlobMetas: []nydus.BlobMetaFile{{Name: parent.Encoded() + ".blob.meta", Data: []byte("parent meta")}},
		}},
		OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
			t.Fatal("downloaded a locally available parent blob")
			return nil, nil
		},
	})
	require.NoError(t, err)
	require.Empty(t, result.ExternalBlobs)
	require.Len(t, result.LocalBlobs, 1)
}

func TestArtifactCompactWithRealBuilder(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER for real compact packaging")
	}
	ctx := context.Background()
	work := t.TempDir()
	store, err := local.NewStore(filepath.Join(work, "content"))
	require.NoError(t, err)
	var sources []Source
	for _, name := range []string{"a", "b"} {
		dir := filepath.Join(work, name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte("data-"+name), 16384), 0o600))
		sources = append(sources, Source{Dir: dir})
	}
	original, err := ConvertMultiSource(ctx, store, MultiSourceOption{
		BuilderPath: builder, WorkDir: work, Sources: sources,
	})
	require.NoError(t, err)
	var manifest ocispec.Manifest
	require.NoError(t, oci.ReadJSON(ctx, store, *original, &manifest))
	pool := filepath.Join(work, "blobs")
	require.NoError(t, os.Mkdir(pool, 0o700))
	blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
	require.NoError(t, err)
	require.Len(t, blobs, 2)
	for _, desc := range blobs {
		data, err := content.ReadBlob(ctx, store, desc)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(pool, desc.Digest.Encoded()), data, 0o600))
	}
	require.NotNil(t, bootstrap)
	require.NoError(t, oci.WalkBootstrapLayer(ctx, store, *bootstrap, func(header *tar.Header, reader *tar.Reader) error {
		if header.Typeflag != tar.TypeReg {
			return nil
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(pool, filepath.Base(header.Name)), data, 0o600)
	}))
	result, err := ConvertNydusArtifacts(ctx, store, ArtifactOption{
		BootstrapPath: filepath.Join(pool, "image.boot"), BlobDir: pool,
		BuilderPath: builder, WorkDir: work, CompactMaxLayers: 1,
	})
	require.NoError(t, err)
	require.Len(t, result.LocalBlobs, 1)
	require.Empty(t, result.ExternalBlobs)
	require.NoError(t, oci.ReadJSON(ctx, store, *result.Descriptor, &manifest))
	require.Len(t, manifest.Layers, 2)
	output := filepath.Dir(result.LocalBlobs[0].Path)
	cmd := exec.CommandContext(ctx, builder, "check", "--bootstrap", filepath.Join(output, "image.boot"), "--blob-dir", output, "--output", "json")
	data, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", data)
	decodedLocal, err := ConvertNydusArtifacts(ctx, store, ArtifactOption{
		BootstrapPath: filepath.Join(pool, "image.boot"), BlobDir: pool,
		BuilderPath: builder, WorkDir: t.TempDir(), CompactMaxLayers: 1,
		CompactCompressor: "none",
	})
	require.NoError(t, err)
	require.Len(t, decodedLocal.LocalBlobs, 1)

	// The same image compacted through seekable remote readers must produce
	// identical content without staging complete source blobs on disk.
	parent, err := LoadParentNydusArtifact(ctx, store, *original, platforms.All)
	require.NoError(t, err)
	var downloaded atomic.Int64
	var total int64
	for _, desc := range parent.Blobs {
		total += desc.Size
	}
	remoteStore, err := local.NewStore(filepath.Join(t.TempDir(), "content"))
	require.NoError(t, err)
	// Matching compression exercises encoded copying; "none" forces decoding
	// the compressible source groups through the reader's sidecar cache.
	for _, compressor := range []string{"", "none"} {
		t.Run("remote-"+compressor, func(t *testing.T) {
			downloaded.Store(0)
			ranged, err := ConvertNydusArtifacts(ctx, remoteStore, ArtifactOption{
				BootstrapPath: filepath.Join(pool, "image.boot"),
				BuilderPath:   builder, WorkDir: t.TempDir(), CompactMaxLayers: 1,
				CompactCompressor: compressor,
				ParentImages:      []ParentImageMetadata{parent},
				OpenCompactBlob: func(_ context.Context, desc ocispec.Descriptor, requestedRange string) (io.ReadSeekCloser, error) {
					if strings.HasPrefix(requestedRange, "bytes=-") {
						return nil, fmt.Errorf("metadata must be reused, not fetched: %s", requestedRange)
					}
					file, err := os.Open(filepath.Join(pool, desc.Digest.Encoded()))
					if err != nil {
						return nil, err
					}
					return countedBlobReader{file, &downloaded}, nil
				},
			})
			require.NoError(t, err)
			require.Len(t, ranged.LocalBlobs, 1)
			expected := result
			if compressor == "none" {
				expected = decodedLocal
			}
			require.Equal(t, expected.LocalBlobs[0].Descriptor.Digest, ranged.LocalBlobs[0].Descriptor.Digest)
			expectedBoot, err := os.ReadFile(expected.BootstrapPath)
			require.NoError(t, err)
			remoteBoot, err := os.ReadFile(ranged.BootstrapPath)
			require.NoError(t, err)
			require.Equal(t, expectedBoot, remoteBoot)
			require.Positive(t, downloaded.Load())
			require.Less(t, downloaded.Load(), total)
			output := filepath.Dir(ranged.LocalBlobs[0].Path)
			data, err := exec.CommandContext(ctx, builder, "check", "--bootstrap", filepath.Join(output, "image.boot"), "--blob-dir", output, "--output", "json").CombinedOutput()
			require.NoError(t, err, "%s", data)
		})
	}
}

func TestRepackStartsRemoteBackendOnlyWhenItMayBeNeeded(t *testing.T) {
	oldRun := runArtifactRepack
	defer func() { runArtifactRepack = oldRun }()
	for _, tc := range []struct {
		name        string
		parent      bool
		count       int
		wantBackend bool
	}{
		{"local blobs only", false, 2, false},
		{"below threshold", true, 1, false},
		{"may exceed threshold", true, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := ArtifactOption{
				WorkDir: t.TempDir(), CompactMaxLayers: 1,
				OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
					t.Fatal("no blob data should be fetched")
					return nil, nil
				},
			}
			if tc.parent {
				opt.ParentImages = []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: digest.FromString("parent")}}}}
			}
			runArtifactRepack = func(_ context.Context, opt ArtifactOption, _, _ string, prepare func(repackReport) error) (repackReport, error) {
				require.Equal(t, tc.wantBackend, opt.repackConfig != "")
				plan := repackReport{}
				return plan, prepare(plan)
			}
			_, work, err := repackArtifact(context.Background(), opt, tc.count, func(repackReport, string) error { return nil })
			require.NoError(t, err)
			require.NoFileExists(t, filepath.Join(work, "backend.json"))
		})
	}
}

func TestCompactCleansIntermediateFilesOnFailure(t *testing.T) {
	oldRun := runArtifactRepack
	defer func() { runArtifactRepack = oldRun }()
	for _, stage := range []string{"download", "builder"} {
		t.Run(stage, func(t *testing.T) {
			work := t.TempDir()
			source := filepath.Join(t.TempDir(), "source")
			require.NoError(t, os.WriteFile(source, []byte("preserved source"), 0o600))
			local := digest.FromString("local")
			remote := digest.FromString("remote")
			runArtifactRepack = func(_ context.Context, opt ArtifactOption, _ string, output string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Compacted: true, Blobs: []string{local.Encoded(), remote.Encoded()}}
				if err := prepare(report); err != nil {
					return report, err
				}
				if stage == "download" {
					_, err := opt.OpenCompactBlob(context.Background(), ocispec.Descriptor{Digest: remote}, "bytes=0-0")
					return report, err
				}
				require.NoError(t, os.MkdirAll(filepath.Join(output, "cache"), 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(output, "cache", "partial"), []byte("cache"), 0o600))
				return report, context.Canceled
			}
			opt := ArtifactOption{
				WorkDir: work,
				OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
					return nil, context.Canceled
				},
			}
			_, _, err := repackArtifact(context.Background(), opt, 2, func(_ repackReport, blobs string) error {
				return stageRepackBlobs(opt,
					[]ocispec.Descriptor{{Digest: local}, {Digest: remote}},
					map[digest.Digest]string{local: source}, blobs, nil)
			})
			require.ErrorIs(t, err, context.Canceled)
			entries, err := os.ReadDir(work)
			require.NoError(t, err)
			require.Empty(t, entries)
			bytes, err := os.ReadFile(source)
			require.NoError(t, err)
			require.Equal(t, "preserved source", string(bytes))
		})
	}
}
