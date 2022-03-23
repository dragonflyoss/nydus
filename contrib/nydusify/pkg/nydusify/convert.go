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

const dirInTar = "image"
const blobNameInTar = "image/image.blob"
const bootstrapNameInTar = "image/image.boot"

type Layer struct {
	Digest digest.Digest
	Reader io.Reader
}

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
			return true, nil
		}),
	); err != nil {
		return errors.Wrap(err, "apply with convert whiteout")
	}

	return nil
}

func unpackNydusTar(ctx context.Context, reader io.Reader) (io.ReadCloser, error) {
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
				if _, err := io.Copy(pw, tr); err != nil {
					pw.CloseWithError(errors.Wrap(err, "copy from tar"))
					return
				}
				found = true
				break
			}
		}

		if !found {
			pw.CloseWithError(errors.Wrapf(err, "not found %s in tar", bootstrapNameInTar))
		}

		pw.Close()
	}()

	return pr, nil
}

func writeNydusTar(ctx context.Context, tw *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "open file for tar")
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "stat file for tar")
	}
	defer file.Close()
	hdr := &tar.Header{
		Name: name,
		Mode: 0444,
		Size: info.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.Wrap(err, "write file header")
	}
	if _, err := io.Copy(tw, file); err != nil {
		return errors.Wrap(err, "copy file to tar")
	}
	return nil
}

func pack(ctx context.Context, blobPath string, bootstrapPath string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	tw := tar.NewWriter(pw)

	go func() {
		dirHdr := &tar.Header{
			Name:     filepath.Dir(dirInTar),
			Mode:     0755,
			Typeflag: tar.TypeDir,
		}
		if err := tw.WriteHeader(dirHdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "write dir header"))
			return
		}

		blobInfo, err := os.Stat(blobPath)
		if err == nil && blobInfo.Size() > 0 {
			if err := writeNydusTar(ctx, tw, blobPath, blobNameInTar); err != nil {
				pw.CloseWithError(errors.Wrap(err, "write blob"))
				return
			}
		}
		if err := writeNydusTar(ctx, tw, bootstrapPath, bootstrapNameInTar); err != nil {
			pw.CloseWithError(errors.Wrap(err, "write bootstrap"))
			return
		}

		defer pw.Close()
		if err := tw.Close(); err != nil {
			pw.CloseWithError(errors.Wrap(err, "close tar writer"))
			return
		}
	}()

	return pr, nil
}

func convert(ctx context.Context, src io.Reader, chunkDictPath string) (io.ReadCloser, error) {
	workDir, err := ioutil.TempDir("", "nydus-converter-")
	if err != nil {
		return nil, errors.Wrap(err, "create work directory")
	}

	sourceDir := filepath.Join(workDir, "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		return nil, errors.Wrap(err, "create source directory")
	}

	if err := unpackOciTar(ctx, sourceDir, src); err != nil {
		return nil, errors.Wrapf(err, "unpack to %s", sourceDir)
	}

	bootstrapPath := filepath.Join(workDir, "bootstrap")
	blobPath := filepath.Join(workDir, "blob")

	if err := tool.Convert(tool.ConvertOption{
		BuilderPath: "nydus-image",

		BootstrapPath: bootstrapPath,
		BlobPath:      blobPath,
		RafsVersion:   "5",
		SourcePath:    sourceDir,
		ChunkDictPath: chunkDictPath,
	}); err != nil {
		return nil, errors.Wrapf(err, "build source %s", sourceDir)
	}

	tr, err := pack(ctx, blobPath, bootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "pack nydus tar")
	}

	return tr, nil
}

func merge(ctx context.Context, layers []Layer, chunkDictPath string) (io.ReadCloser, error) {
	workDir, err := ioutil.TempDir("", "nydus-converter-")
	if err != nil {
		return nil, errors.Wrap(err, "create work directory")
	}

	eg, ctx := errgroup.WithContext(ctx)
	sourceBootstrapPaths := []string{}
	for idx := range layers {
		sourceBootstrapPaths = append(sourceBootstrapPaths, filepath.Join(workDir, layers[idx].Digest.Hex()))
		eg.Go(func(idx int) func() error {
			return func() error {
				layer := layers[idx]
				bootstrap, err := os.Create(filepath.Join(workDir, layer.Digest.Hex()))
				if err != nil {
					return errors.Wrap(err, "create source bootstrap")
				}
				defer bootstrap.Close()
				reader, err := unpackNydusTar(ctx, layer.Reader)
				if err != nil {
					return errors.Wrap(err, "unpack nydus tar")
				}
				defer reader.Close()
				if _, err := io.Copy(bootstrap, reader); err != nil {
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
		ChunkDictPath:        chunkDictPath,
	}); err != nil {
		return nil, errors.Wrap(err, "merge bootstrap")
	}

	reader, err := os.Open(targetBootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "open targe bootstrap")
	}

	return reader, nil
}

func ConvertWithChunkDict(ctx context.Context, src io.Reader, chunkDictPath string) (io.ReadCloser, error) {
	return convert(ctx, src, chunkDictPath)
}

func Convert(ctx context.Context, src io.Reader) (io.ReadCloser, error) {
	return convert(ctx, src, "")
}

func MergeWithChunkDict(ctx context.Context, layers []Layer, chunkDictPath string) (io.ReadCloser, error) {
	return merge(ctx, layers, chunkDictPath)
}

func Merge(ctx context.Context, layers []Layer) (io.ReadCloser, error) {
	return merge(ctx, layers, "")
}
