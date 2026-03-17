package generator

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	providerpkg "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func createFakeBuilderBinary(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nydus-image")
	require.NoError(t, os.WriteFile(path, []byte(script), 0755))
	return path
}

func buildBootstrapArchive(t *testing.T, name string, data []byte) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gz)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}))
	_, err := tarWriter.Write(data)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gz.Close())
	return io.NopCloser(bytes.NewReader(buf.Bytes()))
}

func TestNew(t *testing.T) {
	patches := gomonkey.ApplyFunc(providerpkg.DefaultRemote, func(ref string, insecure bool) (*remote.Remote, error) {
		return &remote.Remote{Ref: ref}, nil
	})
	defer patches.Reset()
	parserPatches := gomonkey.ApplyFunc(parser.New, func(r *remote.Remote, interestedArch string) (*parser.Parser, error) {
		return &parser.Parser{Remote: r}, nil
	})
	defer parserPatches.Reset()

	generator, err := New(Opt{Sources: []string{"repo/a:latest", "repo/b:latest"}, SourceInsecure: true, ExpectedArch: "amd64"})
	require.NoError(t, err)
	require.Len(t, generator.sourcesParser, 2)
	require.Equal(t, "repo/a:latest", generator.sourcesParser[0].Remote.Ref)
}

func TestHosts(t *testing.T) {
	generator := &Generator{Opt: Opt{Sources: []string{"src1", "src2"}, Target: "target", SourceInsecure: true, TargetInsecure: false}}
	hostFunc := hosts(generator)

	_, insecure, err := hostFunc("src2")
	require.NoError(t, err)
	require.True(t, insecure)

	_, insecure, err = hostFunc("target")
	require.NoError(t, err)
	require.False(t, insecure)

	_, insecure, err = hostFunc("unknown")
	require.NoError(t, err)
	require.False(t, insecure)
}

func TestGenerate(t *testing.T) {
	t.Run("absolute workdir success", func(t *testing.T) {
		workDir := t.TempDir()
		argsFile := filepath.Join(workDir, "args.txt")
		builderPath := createFakeBuilderBinary(t, "#!/bin/sh\nprintf '%s\n' \"$@\" > \""+argsFile+"\"\n")

		generator := &Generator{Opt: Opt{WorkDir: workDir, NydusImagePath: builderPath}}
		bootstrapPath, outputPath, err := generator.generate(context.Background(), []string{"boot-1", "boot-2"})
		require.NoError(t, err)
		require.Equal(t, filepath.Join(workDir, "chunkdict_bootstrap"), bootstrapPath)
		require.Equal(t, filepath.Join(workDir, "nydus_bootstrap_output.json"), outputPath)

		args, err := os.ReadFile(argsFile)
		require.NoError(t, err)
		argsText := string(args)
		require.Contains(t, argsText, "chunkdict")
		require.Contains(t, argsText, "generate")
		require.Contains(t, argsText, filepath.Join(workDir, "database.db"))
		require.Contains(t, argsText, "boot-1")
		require.Contains(t, argsText, "boot-2")
	})

	t.Run("builder failure", func(t *testing.T) {
		workDir := t.TempDir()
		builderPath := createFakeBuilderBinary(t, "#!/bin/sh\nexit 1\n")

		generator := &Generator{Opt: Opt{WorkDir: workDir, NydusImagePath: builderPath}}
		_, _, err := generator.generate(context.Background(), []string{"boot-1"})
		require.ErrorContains(t, err, "invalid nydus bootstrap format")
	})
}

func TestOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		generator := &Generator{sourcesParser: []*parser.Parser{{Remote: &remote.Remote{Ref: "docker.io/library/busybox:latest"}}}}
		patches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
			return buildBootstrapArchive(t, utils.BootstrapFileNameInLayer, []byte("bootstrap-data")), nil
		})
		defer patches.Reset()

		outputDir := t.TempDir()
		err := generator.Output(context.Background(), &parser.Parsed{
			Index:      &ocispec.Index{},
			NydusImage: &parser.Image{Manifest: ocispec.Manifest{}, Config: ocispec.Image{}},
		}, outputDir, 0)
		require.NoError(t, err)
		for _, name := range []string{"nydus_index.json", "nydus_manifest.json", "nydus_config.json", "nydus_bootstrap"} {
			_, err := os.Stat(filepath.Join(outputDir, name))
			require.NoError(t, err)
		}
	})

	t.Run("not nydus image", func(t *testing.T) {
		generator := &Generator{sourcesParser: []*parser.Parser{{Remote: &remote.Remote{Ref: "docker.io/library/busybox:latest"}}}}
		err := generator.Output(context.Background(), &parser.Parsed{}, t.TempDir(), 0)
		require.ErrorContains(t, err, "is not a Nydus image")
	})
}

func TestPrettyDump(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "object.json")
	require.NoError(t, prettyDump(map[string]string{"hello": "nydus"}, outputPath))
	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "hello")
	require.Contains(t, string(content), "nydus")
}

func TestPull(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		patches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(*parser.Parser, context.Context) (*parser.Parsed, error) {
			return &parser.Parsed{NydusImage: &parser.Image{}}, nil
		})
		defer patches.Reset()

		outputPatches := gomonkey.ApplyMethod(reflect.TypeOf(&Generator{}), "Output", func(_ *Generator, _ context.Context, _ *parser.Parsed, outputPath string, _ int) error {
			require.NoError(t, os.WriteFile(filepath.Join(outputPath, "nydus_bootstrap"), []byte("bootstrap"), 0o644))
			return nil
		})
		defer outputPatches.Reset()

		workDir := t.TempDir()
		generator := &Generator{
			Opt:           Opt{Sources: []string{"docker.io/library/busybox:latest"}, WorkDir: workDir},
			sourcesParser: []*parser.Parser{{Remote: &remote.Remote{Ref: "docker.io/library/busybox:latest"}}},
		}

		paths, err := generator.pull(context.Background())
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.Equal(t, filepath.Join(workDir, "docker.io:library:busybox:latest", "nydus_bootstrap"), paths[0])
	})

	t.Run("parse error", func(t *testing.T) {
		patches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(*parser.Parser, context.Context) (*parser.Parsed, error) {
			return nil, errors.New("parse error")
		})
		defer patches.Reset()

		generator := &Generator{
			Opt:           Opt{Sources: []string{"docker.io/library/busybox:latest"}, WorkDir: t.TempDir()},
			sourcesParser: []*parser.Parser{{Remote: &remote.Remote{Ref: "docker.io/library/busybox:latest"}}},
		}

		_, err := generator.pull(context.Background())
		require.ErrorContains(t, err, "parse Nydus image")
	})
}

func TestNewStore(t *testing.T) {
	remotes := []ocispec.Descriptor{
		{Digest: digest.FromString("blob1"), Size: 100},
		{Digest: digest.FromString("blob2"), Size: 200},
	}
	s := newStore(nil, remotes)
	require.NotNil(t, s)
	require.Len(t, s.remotes, 2)
}

func TestStoreInfoFromRemotes(t *testing.T) {
	dgst := digest.FromString("blob1")
	remotes := []ocispec.Descriptor{
		{Digest: dgst, Size: 100},
	}
	// Create a store with a nil base - Info will fail on base, then search remotes
	baseDir := t.TempDir()
	baseStore, err := local.NewStore(baseDir)
	require.NoError(t, err)

	s := newStore(baseStore, remotes)
	info, err := s.Info(context.Background(), dgst)
	require.NoError(t, err)
	require.Equal(t, dgst, info.Digest)
	require.Equal(t, int64(100), info.Size)
}

func TestStoreInfoNotFound(t *testing.T) {
	baseDir := t.TempDir()
	baseStore, err := local.NewStore(baseDir)
	require.NoError(t, err)

	s := newStore(baseStore, nil)
	_, err = s.Info(context.Background(), digest.FromString("missing"))
	require.Error(t, err)
}
