package nydus

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildArgumentsMatchLayouts(t *testing.T) {
	for _, compressor := range []string{"", "none", "zstd", "lz4", "erofs-none", "erofs-lz4", "erofs-zstd"} {
		t.Run(compressor, func(t *testing.T) {
			for _, sourceType := range []string{"", "dir", "tar"} {
				args, err := (BuildOption{SourceDir: "source", BlobPath: "blob", Compressor: compressor, SourceType: sourceType}).args()
				if err != nil {
					t.Fatal(err)
				}
				flags := make(map[string]string)
				for index := 2; index < len(args); index += 2 {
					flags[args[index]] = args[index+1]
				}
				if flags["--chunk-size"] != strconv.Itoa(DefaultChunkSize) {
					t.Fatalf("unexpected geometry: %v", args)
				}
				if sourceType == "" {
					sourceType = "dir"
				}
				if flags["--source-type"] != sourceType {
					t.Fatalf("unexpected source type: %v", args)
				}
			}
		})
	}
}

func TestBuildRejectsUnsupportedTarOptions(t *testing.T) {
	for _, option := range []BuildOption{{SourceType: "invalid"}, {SourceType: "tar", Excludes: []string{"secret"}}} {
		if _, err := option.args(); err == nil {
			t.Fatalf("expected rejection: %+v", option)
		}
	}
}

func TestIsNydusCompressor(t *testing.T) {
	tests := []struct {
		name       string
		compressor string
		expect     func(t *testing.T, ok bool)
	}{
		{
			name:       "chunk layout",
			compressor: "lz4",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "native erofs layout",
			compressor: "erofs-zstd",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "unsupported compressor",
			compressor: "gzip",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name: "empty compressor",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, IsNydusCompressor(tc.compressor))
		})
	}
}

func TestBuildOption_args(t *testing.T) {
	tests := []struct {
		name   string
		opt    BuildOption
		expect func(t *testing.T, args []string, err error)
	}{
		{
			name: "directory exclusions are forwarded",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", Excludes: []string{"secret", "cache"}},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"--exclude", "secret", "--exclude", "cache"}, args[len(args)-4:])
			},
		},
		{
			name: "explicit log level and chunk size",
			opt:  BuildOption{SourceDir: "source", BlobPath: "blob", ChunkSize: 1 << 20, LogLevel: "debug"},
			expect: func(t *testing.T, args []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{"build", "source", "--source-type", "dir", "--blob", "blob", "--chunk-size", "1048576", "--compressor", DefaultCompressor, "--log-level", "debug"}, args)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := tc.opt.args()
			tc.expect(t, args, err)
		})
	}
}

func TestRunNydusBuild(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		opt    BuildOption
		expect func(t *testing.T, blobPath string, err error)
	}{
		{
			name: "streams stdin source into blob",
			body: "test \"$type\" = tar\ncat \"$source\" > \"$blob\"\n",
			opt:  BuildOption{SourceDir: "/dev/stdin", SourceType: "tar", Stdin: strings.NewReader("layer tar")},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(blobPath)
				assert.NoError(err)
				assert.Equal("layer tar", string(data))
			},
		},
		{
			name: "invalid options do not run the builder",
			body: ": > \"$blob\"\n",
			opt:  BuildOption{SourceDir: "source", SourceType: "tar", Excludes: []string{"secret"}},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "tar sources do not support path exclusions")
				assert.NoFileExists(blobPath)
			},
		},
		{
			name: "builder failure carries stderr",
			body: "echo invalid source >&2\nexit 3\n",
			opt:  BuildOption{SourceDir: "source"},
			expect: func(t *testing.T, blobPath string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus build: invalid source")
				assert.ErrorContains(err, "exit status 3")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opt.BuilderPath = fakeBuilder(t, tc.body)
			tc.opt.BlobPath = filepath.Join(t.TempDir(), "blob")
			tc.expect(t, tc.opt.BlobPath, RunNydusBuild(context.Background(), tc.opt))
		})
	}
}

func TestRunNydusExport(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		expect func(t *testing.T, output string, err error)
	}{
		{
			name: "streams exported tar to destination",
			body: "test -f \"$source\"\nprintf 'exported tar'\n",
			expect: func(t *testing.T, output string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("exported tar", output)
			},
		},
		{
			name: "builder failure carries stderr",
			body: "echo corrupt blob >&2\nexit 1\n",
			expect: func(t *testing.T, output string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus export: corrupt blob")
				assert.Empty(output)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blobPath := filepath.Join(t.TempDir(), "blob")
			if !assert.NoError(t, os.WriteFile(blobPath, []byte("blob"), 0o600)) {
				t.FailNow()
			}
			var output bytes.Buffer
			err := RunNydusExport(context.Background(), ExportOption{BuilderPath: fakeBuilder(t, tc.body), BlobPath: blobPath}, &output)
			tc.expect(t, output.String(), err)
		})
	}
}
