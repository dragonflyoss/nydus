package pipeline

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockRepackPlan = repackReport{Version: 1, Phase: "plan", Pruned: true, Blobs: []string{mockBlobDigest.Encoded()}}

	mockRepackResult = repackReport{Version: 1, Phase: "result", Pruned: true, Blobs: []string{mockBlobDigest.Encoded()}}
)

func mockRepackJSON(t *testing.T, report repackReport) string {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func mockRepackScript(t *testing.T, plan, result repackReport) string {
	t.Helper()
	return fmt.Sprintf("printf '%%s\\n' '%s'\nread -r ready || exit 7\n[ \"$ready\" = ready ] || exit 8\nprintf '%%s\\n' '%s'", mockRepackJSON(t, plan), mockRepackJSON(t, result))
}

func mockEmptyRepack(_ context.Context, _ ArtifactOption, _, _ string, prepare func(repackReport) error) (repackReport, error) {
	return repackReport{}, prepare(repackReport{})
}

func mockIsolatedRun(t *testing.T) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$")
	if cover := flag.Lookup("test.gocoverdir"); cover != nil && cover.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+cover.Value.String())
	}
	cmd.Env = append(os.Environ(), "NYDUS_TEST_REPACK_FD_LIMIT=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func mockFileLimit(t *testing.T, free int) {
	t.Helper()
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}

	bounded := limit
	bounded.Cur = min(limit.Cur, 64)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &bounded); err != nil {
		t.Fatal(err)
	}

	var files []*os.File
	t.Cleanup(func() {
		for _, file := range files {
			_ = file.Close()
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
	})
	for {
		file, err := os.Open(os.DevNull)
		if errors.Is(err, syscall.EMFILE) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	if len(files) < free {
		t.Fatalf("opened %d files, need %d free", len(files), free)
	}

	for _, file := range files[len(files)-free:] {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	files = files[:len(files)-free]
}

func TestExecuteArtifactRepack(t *testing.T) {
	tests := []struct {
		name    string
		builder string
		script  string
		prepare error
		expect  func(t *testing.T, result repackReport, prepared []string, err error)
	}{
		{
			name:   "complete preparation protocol",
			script: mockRepackScript(t, mockRepackPlan, mockRepackResult),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockRepackPlan.Blobs, prepared)
				assert.Equal(mockRepackResult, result)
			},
		},
		{
			name:    "abort on prepare failure",
			script:  mockRepackScript(t, mockRepackPlan, mockRepackResult),
			prepare: context.Canceled,
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				assert.Equal(mockRepackPlan.Blobs, prepared)
			},
		},
		{
			name:   "reject unsupported plan version",
			script: mockRepackScript(t, repackReport{Version: 2, Phase: "plan"}, mockRepackResult),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid repack plan version or phase")
			},
		},
		{
			name:   "reject result phase as plan",
			script: mockRepackScript(t, mockRepackResult, mockRepackResult),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid repack plan version or phase")
			},
		},
		{
			name:   "reject invalid plan digest",
			script: mockRepackScript(t, repackReport{Version: 1, Phase: "plan", Blobs: []string{"invalid"}}, mockRepackResult),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid repack blob digest")
			},
		},
		{
			name:   "reject duplicate plan digest",
			script: mockRepackScript(t, repackReport{Version: 1, Phase: "plan", Blobs: []string{mockBlobDigest.Encoded(), mockBlobDigest.Encoded()}}, mockRepackResult),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "duplicate repack blob digest")
			},
		},
		{
			name:   "reject changed decision",
			script: mockRepackScript(t, mockRepackPlan, repackReport{Version: 1, Phase: "result", Compacted: true}),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "repack result does not match preparation plan")
				assert.Equal(mockRepackPlan.Blobs, prepared)
			},
		},
		{
			name:   "reject changed references",
			script: mockRepackScript(t, mockRepackPlan, repackReport{Version: 1, Phase: "result", Pruned: true}),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "prune changed planned source blob identities")
				assert.Equal(mockRepackPlan.Blobs, prepared)
			},
		},
		{
			name:    "reject missing builder",
			builder: "/nonexistent/nydus",
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "no such file")
			},
		},
		{
			name:   "reject invalid plan",
			script: "printf 'invalid'",
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read repack plan")
			},
		},
		{
			name:   "reject closed input",
			script: "exec 0<&-; printf '%s\\n' '" + mockRepackJSON(t, mockRepackPlan) + "'; exec sleep 10",
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "broken pipe")
			},
		},
		{
			name:   "reject invalid result",
			script: "printf '%s\\n' '" + mockRepackJSON(t, mockRepackPlan) + "'; read -r ready; printf 'invalid'",
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read repack result")
			},
		},
		{
			name:   "reject failed builder",
			script: "printf '%s\\n' '" + mockRepackJSON(t, mockRepackPlan) + "'; read -r ready; printf '%s\\n' '" + mockRepackJSON(t, mockRepackResult) + "'; exit 7",
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "exit status 7")
			},
		},
		{
			name:   "reject invalid result digest",
			script: mockRepackScript(t, mockRepackPlan, repackReport{Version: 1, Phase: "result", Pruned: true, Blobs: []string{"invalid"}}),
			expect: func(t *testing.T, result repackReport, prepared []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid repack blob digest")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var prepared []string
			opt := ArtifactOption{BuilderPath: cmp.Or(tc.builder, mockBuilder(t, tc.script))}
			result, err := executeArtifactRepack(context.Background(), opt, t.TempDir(), t.TempDir(), func(report repackReport) error {
				prepared = report.Blobs
				return tc.prepare
			})

			tc.expect(t, result, prepared, err)
		})
	}
}

func TestRepackArtifact(t *testing.T) {
	run := runArtifactRepack
	defer func() { runArtifactRepack = run }()

	tests := []struct {
		name      string
		opt       func(t *testing.T) ArtifactOption
		count     int
		descs     []ocispec.Descriptor
		run       func(ctx context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error)
		fileLimit bool
		freeFiles int
		expect    func(t *testing.T, opt ArtifactOption, source, config, work string, err error)
	}{
		{
			name: "reject unsupported compressor",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{CompactCompressor: "invalid", WorkDir: t.TempDir()}
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `unsupported compact compressor "invalid"`)
			},
		},
		{
			name: "reject missing work directory",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{}
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "repack requires a work directory")
			},
		},
		{
			name: "reject regular file work directory",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{WorkDir: mockFile(t, filepath.Join(t.TempDir(), "file"), nil)}
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.ENOTDIR)
			},
		},
		{
			name: "reject read only work filesystem",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{WorkDir: "/proc/self"}
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name: "skip backend for local blobs only",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{WorkDir: t.TempDir(), CompactMaxLayers: 1, OpenCompactBlob: mockUnavailableBlob}
			},
			count: 2,
			run:   mockEmptyRepack,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(config)
				assert.NoFileExists(filepath.Join(work, "backend.json"))
			},
		},
		{
			name: "skip backend below compact threshold",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{
					WorkDir:          t.TempDir(),
					CompactMaxLayers: 1,
					ParentImages:     []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: mockOtherBlobDigest}}}},
					OpenCompactBlob:  mockUnavailableBlob,
				}
			},
			count: 1,
			run:   mockEmptyRepack,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(config)
				assert.NoFileExists(filepath.Join(work, "backend.json"))
			},
		},
		{
			name: "start backend above compact threshold",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{
					WorkDir:          t.TempDir(),
					CompactMaxLayers: 1,
					ParentImages:     []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: mockOtherBlobDigest}}}},
					OpenCompactBlob:  mockUnavailableBlob,
				}
			},
			count: 2,
			run:   mockEmptyRepack,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(filepath.Join(work, "backend.json"), config)
				assert.NoFileExists(filepath.Join(work, "backend.json"))
			},
		},
		{
			name: "clean work after failed download",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{
					WorkDir: t.TempDir(),
					OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
						return nil, context.Canceled
					},
				}
			},
			count: 2,
			descs: []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockOtherBlobDigest}},
			run: func(ctx context.Context, opt ArtifactOption, _, _ string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded(), mockOtherBlobDigest.Encoded()}}
				if err := prepare(report); err != nil {
					return report, err
				}

				_, err := opt.OpenCompactBlob(ctx, ocispec.Descriptor{Digest: mockOtherBlobDigest}, "bytes=0-0")
				return report, err
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name: "clean work after failed builder",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{
					WorkDir: t.TempDir(),
					OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
						return nil, context.Canceled
					},
				}
			},
			count: 2,
			descs: []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockOtherBlobDigest}},
			run: func(_ context.Context, _ ArtifactOption, _, output string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded(), mockOtherBlobDigest.Encoded()}}
				if err := prepare(report); err != nil {
					return report, err
				}
				if err := os.MkdirAll(filepath.Join(output, "cache"), 0o700); err != nil {
					return report, err
				}
				if err := os.WriteFile(filepath.Join(output, "cache", "partial"), []byte("cache"), 0o600); err != nil {
					return report, err
				}

				return report, context.Canceled
			},
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)

				entries, err := os.ReadDir(opt.WorkDir)
				assert.NoError(err)
				assert.Empty(entries)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name: "reject exhausted stdout pipe",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{BuilderPath: "/bin/true", WorkDir: t.TempDir()}
			},
			run:       executeArtifactRepack,
			fileLimit: true,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.EMFILE)
			},
		},
		{
			name: "reject exhausted stdin pipe",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{BuilderPath: "/bin/true", WorkDir: t.TempDir()}
			},
			run:       executeArtifactRepack,
			fileLimit: true,
			freeFiles: 2,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.EMFILE)
			},
		},
		{
			name: "reject exhausted backend listener",
			opt: func(t *testing.T) ArtifactOption {
				return ArtifactOption{
					WorkDir:          t.TempDir(),
					CompactMaxLayers: 1,
					ParentImages:     []ParentImageMetadata{{}},
					OpenCompactBlob:  mockUnavailableBlob,
				}
			},
			count: 2,
			run: func(context.Context, ArtifactOption, string, string, func(repackReport) error) (repackReport, error) {
				return repackReport{}, errors.New("unexpected repack run")
			},
			fileLimit: true,
			expect: func(t *testing.T, opt ArtifactOption, source, config, work string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.EMFILE)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fileLimit && os.Getenv("NYDUS_TEST_REPACK_FD_LIMIT") == "" {
				mockIsolatedRun(t)
				return
			}

			source := mockFile(t, filepath.Join(t.TempDir(), "source"), mockBlobData)
			opt := tc.opt(t)
			var config string
			runArtifactRepack = func(ctx context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error) {
				config = opt.repackConfig
				return tc.run(ctx, opt, blobs, output, prepare)
			}
			if tc.fileLimit {
				mockFileLimit(t, tc.freeFiles)
			}

			_, work, err := repackArtifact(context.Background(), opt, tc.count, func(_ repackReport, blobs string) error {
				return stageRepackBlobs(opt, tc.descs, map[digest.Digest]string{mockBlobDigest: source}, blobs, nil)
			})

			tc.expect(t, opt, source, config, work, err)
		})
	}
}

func TestStageRepackBlobs(t *testing.T) {
	tests := []struct {
		name   string
		opt    ArtifactOption
		local  bool
		mock   func(t *testing.T, work, blobs string)
		expect func(t *testing.T, source string, err error)
	}{
		{
			name: "reject blob without data",
			mock: func(t *testing.T, work, blobs string) {},
			expect: func(t *testing.T, source string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "compact needs data for blob "+mockBlobDigest.String())

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name:  "reject existing destination",
			local: true,
			mock: func(t *testing.T, work, blobs string) {
				mockFile(t, filepath.Join(blobs, mockBlobDigest.Encoded()), nil)
			},
			expect: func(t *testing.T, source string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "prepare compact blob "+mockBlobDigest.String())

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name:  "reject blocked cache directory",
			local: true,
			mock: func(t *testing.T, work, blobs string) {
				mockFile(t, filepath.Join(work, "output"), nil)
			},
			expect: func(t *testing.T, source string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.ENOTDIR)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name:  "reject blocked blob meta",
			local: true,
			mock: func(t *testing.T, work, blobs string) {
				if err := os.MkdirAll(filepath.Join(work, "output", "cache", mockBlobMetaFile.Name), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, source string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stage compact metadata "+mockBlobMetaFile.Name)

				data, err := os.ReadFile(source)
				assert.NoError(err)
				assert.Equal(mockBlobData, data)
			},
		},
		{
			name: "reject blocked remote descriptor",
			opt:  ArtifactOption{OpenCompactBlob: mockUnavailableBlob},
			mock: func(t *testing.T, work, blobs string) {
				if err := os.Mkdir(filepath.Join(blobs, mockBlobDigest.Encoded()+".descriptor.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, source string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "prepare compact blob "+mockBlobDigest.String())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			blobs := filepath.Join(work, "blobs")
			if err := os.Mkdir(blobs, 0o700); err != nil {
				t.Fatal(err)
			}

			source := mockFile(t, filepath.Join(work, "source"), mockBlobData)
			paths := map[digest.Digest]string{}
			if tc.local {
				paths[mockBlobDigest] = source
			}
			tc.mock(t, work, blobs)
			err := stageRepackBlobs(tc.opt, []ocispec.Descriptor{{Digest: mockBlobDigest}}, paths, blobs, []nydus.BlobMetaFile{mockBlobMetaFile})

			tc.expect(t, source, err)
		})
	}
}
