package converter

import (
	"archive/tar"
	"context"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/nydusify/tool"
)

const dirNameInTar = "image"
const blobNameInTar = "image/image.blob"
const bootstrapNameInTar = "image/image.boot"

const envNydusBuilder = "NYDUS_BUILDER"
const envNydusWorkdir = "NYDUS_WORKDIR"

type Layer struct {
	// Digest represents the hash of whole tar blob.
	Digest digest.Digest
	// Reader holds the reader of whole tar blob.
	Reader io.Reader
}

type ConvertOption struct {
	// ChunkDictPath holds the bootstrap path of chunk dict image.
	ChunkDictPath string
	// PrefetchPatterns holds file path pattern list want to prefetch.
	PrefetchPatterns string
}

type MergeOption struct {
	// ChunkDictPath holds the bootstrap path of chunk dict image.
	ChunkDictPath string
	// PrefetchPatterns holds file path pattern list want to prefetch.
	PrefetchPatterns string
}

// Unpack a OCI formatted tar stream into a directory.
func unpackOciTar(ctx context.Context, dst string, reader io.Reader) error {
	ds, err := compression.DecompressStream(reader)
	if err != nil {
		return errors.Wrap(err, "decompress stream")
	}
	defer ds.Close()

	if _, err := archive.Apply(
		ctx,
		dst,
		ds,
		archive.WithConvertWhiteout(func(hdr *tar.Header, file string) (bool, error) {
			// Keep to extract all whiteout files.
			return true, nil
		}),
	); err != nil {
		return errors.Wrap(err, "apply with convert whiteout")
	}

	return nil
}

// Unpack the bootstrap in Nydus formatted tar stream (blob + bootstrap).
func unpackBootstrapFromNydusTar(ctx context.Context, reader io.Reader) (io.ReadCloser, error) {
	pr, pw := io.Pipe()

	go func() {
		rdr, err := compression.DecompressStream(reader)
		if err != nil {
			pw.CloseWithError(errors.Wrap(err, "apply with convert whiteout"))
			return
		}
		defer rdr.Close()

		found := false
		tr := tar.NewReader(rdr)
		for {
			hdr, err := tr.Next()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					pw.CloseWithError(errors.Wrap(err, "seek tar"))
					return
				}
			}
			if hdr.Name == bootstrapNameInTar {
				if _, err := io.Copy(pw, newCtxReader(ctx, tr)); err != nil {
					pw.CloseWithError(errors.Wrap(err, "copy from tar"))
					return
				}
				found = true
				break
			}
		}

		if !found {
			pw.CloseWithError(errors.Wrapf(err, "not found %s in tar", bootstrapNameInTar))
			return
		}

		pw.Close()
	}()

	return pr, nil
}

// Write nydus artifact (blob/bootstrap) into a tar stream.
func writeNydusTar(ctx context.Context, tw *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "open file for tar")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "stat file for tar")
	}

	hdr := &tar.Header{
		Name: name,
		Mode: 0444,
		Size: info.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.Wrap(err, "write file header")
	}

	if _, err := io.Copy(tw, newCtxReader(ctx, file)); err != nil {
		return errors.Wrap(err, "copy file to tar")
	}

	return nil
}

// Pack nydus blob and bootstrap to a tar stream
func pack(ctx context.Context, blobPath string, bootstrapPath string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	tw := tar.NewWriter(pw)

	go func() {
		defer pw.Close()

		// Write a directory into tar stream.
		dirHdr := &tar.Header{
			Name:     filepath.Dir(dirNameInTar),
			Mode:     0755,
			Typeflag: tar.TypeDir,
		}
		if err := tw.WriteHeader(dirHdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "write dir header"))
			return
		}

		// Write nydus blob into tar stream.
		blobInfo, err := os.Stat(blobPath)
		if err == nil && blobInfo.Size() > 0 {
			if err := writeNydusTar(ctx, tw, blobPath, blobNameInTar); err != nil {
				pw.CloseWithError(errors.Wrap(err, "write blob"))
				return
			}
		}
		// Write nydus bootstrap into tar stream.
		if err := writeNydusTar(ctx, tw, bootstrapPath, bootstrapNameInTar); err != nil {
			pw.CloseWithError(errors.Wrap(err, "write bootstrap"))
			return
		}

		if err := tw.Close(); err != nil {
			pw.CloseWithError(errors.Wrap(err, "close tar writer"))
			return
		}
	}()

	return pr, nil
}

// Convert converts a OCI formatted tar stream to a nydus formatted tar stream.
//
// The nydus blob tar stream contains blob and bootstrap files with the following
// file tree structure:
//
// /image
// ├── image.blob
// ├── image.boot
//
// So for the chunk of files in the nydus boostreap, a blob compressed offset
// of 1024 (size_of(tar_header) * 2) is required.
func Convert(ctx context.Context, src io.Reader, opt ConvertOption) (io.ReadCloser, error) {
	workDir, err := ioutil.TempDir(os.Getenv(envNydusWorkdir), "nydus-converter-")
	if err != nil {
		return nil, errors.Wrap(err, "create work directory")
	}
	defer func() {
		if err != nil {
			os.RemoveAll(workDir)
		}
	}()

	sourceDir := filepath.Join(workDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		return nil, errors.Wrap(err, "create source directory")
	}

	if err := unpackOciTar(ctx, sourceDir, src); err != nil {
		return nil, errors.Wrapf(err, "unpack to %s", sourceDir)
	}

	bootstrapPath := filepath.Join(workDir, "bootstrap")
	blobPath := filepath.Join(workDir, "blob")

	builderPath := os.Getenv(envNydusBuilder)
	if builderPath == "" {
		builderPath = "nydus-image"
	}
	if err := tool.Convert(tool.ConvertOption{
		BuilderPath: builderPath,

		BootstrapPath:    bootstrapPath,
		BlobPath:         blobPath,
		RafsVersion:      "5",
		SourcePath:       sourceDir,
		ChunkDictPath:    opt.ChunkDictPath,
		PrefetchPatterns: opt.PrefetchPatterns,
	}); err != nil {
		return nil, errors.Wrapf(err, "build source %s", sourceDir)
	}

	tr, err := pack(ctx, blobPath, bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "pack nydus tar")
	}

	return newActionCloser(tr, func() error {
		return os.RemoveAll(workDir)
	}), nil
}

// Merge multiple nydus boostraps (from every layer of image) to a final boostrap.
func Merge(ctx context.Context, layers []Layer, opt MergeOption) (reader io.ReadCloser, err error) {
	workDir, err := ioutil.TempDir("", "nydus-converter-")
	if err != nil {
		return nil, errors.Wrap(err, "create work directory")
	}
	defer func() {
		if err != nil {
			os.RemoveAll(workDir)
		}
	}()

	eg, ctx := errgroup.WithContext(ctx)
	sourceBootstrapPaths := []string{}
	for idx := range layers {
		sourceBootstrapPaths = append(sourceBootstrapPaths, filepath.Join(workDir, layers[idx].Digest.Hex()))
		eg.Go(func(idx int) func() error {
			return func() error {
				layer := layers[idx]

				// Use the hex hash string of whole tar blob as the boostrap name.
				bootstrap, err := os.Create(filepath.Join(workDir, layer.Digest.Hex()))
				if err != nil {
					return errors.Wrap(err, "create source bootstrap")
				}
				defer bootstrap.Close()

				bootstrapReader, err := unpackBootstrapFromNydusTar(ctx, layer.Reader)
				if err != nil {
					return errors.Wrap(err, "unpack nydus tar")
				}
				defer bootstrapReader.Close()

				if _, err := io.Copy(bootstrap, newCtxReader(ctx, bootstrapReader)); err != nil {
					return errors.Wrap(err, "copy bootstrap from tar")
				}

				return nil
			}
		}(idx))
	}

	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "unpack all bootstraps")
	}

	targetBootstrapPath := filepath.Join(workDir, "bootstrap")

	if err := tool.Merge(tool.MergeOption{
		BuilderPath: "nydus-image",

		SourceBootstrapPaths: sourceBootstrapPaths,
		TargetBootstrapPath:  targetBootstrapPath,
		ChunkDictPath:        opt.ChunkDictPath,
		PrefetchPatterns:     opt.PrefetchPatterns,
	}); err != nil {
		return nil, errors.Wrap(err, "merge bootstrap")
	}

	reader, err = os.Open(targetBootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "open targe bootstrap")
	}

	return newActionCloser(reader, func() error {
		return os.RemoveAll(workDir)
	}), nil
}
