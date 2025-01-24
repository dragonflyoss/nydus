package copier

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	RAFS_MAGIC           = 0x52414653
	RAFS_RUST_VERSION    = 0x500
	RAFS_ROOT_ID         = 1
	RAFS_SUPERBLOCK_SIZE = 8192
	RAFS_BLOCK_SIZE      = 1024 * 1024
	RAFS_INODE_SIZE      = 128
	RAFS_CHUNK_SIZE      = 80
)

type v5ondiskSuperblock struct {
	Magic                  uint32
	Version                uint32
	SbSize                 uint32
	BlockSize              uint32
	Flags                  uint64
	InodesCount            uint64
	InodeTableOffset       uint64
	PrefetchTableOffset    uint64
	BlobTableOffset        uint64
	InodeTableEntries      uint32
	PrefetchTableEntries   uint32
	BlobTableSize          uint32
	ExtendBlobTableEntries uint32
	ExtendBlobTableOffset  uint64
}

func copyFile(sourceFile, destFile string) error {
	source, err := os.Open(sourceFile)
	if err != nil {
		return errors.Wrapf(err, "failed to find source file %s", sourceFile)
	}
	defer source.Close()
	dest, err := os.Create(destFile)
	if err != nil {
		return errors.Wrapf(err, "failed to create %s", destFile)
	}
	defer dest.Close()
	if _, err = io.Copy(dest, source); err != nil {
		return errors.Wrap(err, "failed to copy config")
	}
	return nil
}

func fileDigest(bootstrap string) (string, int64, error) {
	fp, err := os.Open(bootstrap)
	if err != nil {
		return "", 0, err
	}
	defer fp.Close()

	digest, err := calcDigest(fp)
	if err != nil {
		return "", 0, err
	}

	info, err := os.Stat(bootstrap)
	if err != nil {
		return "", 0, err
	}

	return digest, info.Size(), nil
}

func readBytes(fp *os.File, n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	_, err := fp.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func calcDigest(reader io.Reader) (string, error) {
	h := sha256.New()
	_, err := io.Copy(h, reader)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fixBlobDigests(sourceBootstrap, targetBootstrap string, blobMap map[string]string) error {
	sourceBootstrapFile, err := os.OpenFile(sourceBootstrap, os.O_RDONLY, 0755)
	if err != nil {
		return errors.Wrap(err, "open source bootstrap")
	}
	defer sourceBootstrapFile.Close()

	// Parse super block
	var sb v5ondiskSuperblock
	if err = binary.Read(sourceBootstrapFile, binary.LittleEndian, &sb); err != nil {
		return errors.Wrap(err, "read super block")
	}
	if sb.Magic != RAFS_MAGIC {
		return fmt.Errorf("invalid magic number: %d", sb.Magic)
	}
	if sb.Version < RAFS_RUST_VERSION {
		return fmt.Errorf("invalid rafs version: %d", sb.Version)
	}

	// Parse blob table
	_, err = sourceBootstrapFile.Seek(int64(sb.BlobTableOffset), io.SeekStart)
	if err != nil {
		return errors.Wrap(err, "seek blob table offset")
	}
	blobTableBytes, err := readBytes(sourceBootstrapFile, int(sb.BlobTableSize))
	if err != nil {
		return errors.Wrap(err, "read blob table")
	}

	// Replace blob digests
	start := 8
	idx := 8
	for idx < len(blobTableBytes) {
		if blobTableBytes[idx] == 0 || idx == len(blobTableBytes)-1 {
			end := idx
			if blobTableBytes[idx] != 0 {
				end = idx + 1
			}
			blobDigest := blobTableBytes[start:end]
			for oldDigest, newDigest := range blobMap {
				if oldDigest == string(blobDigest) {
					logrus.Infof("fix blob digest %s -> %s", blobDigest, newDigest)
					blobTableBytes = bytes.Replace(blobTableBytes, blobDigest, []byte(newDigest), -1)
				}
			}
			start = idx + 9 // \0 and header(u32,u32)
			idx = start
		} else {
			idx++
		}
	}

	// Write back to target bootstrap
	if sourceBootstrap != targetBootstrap {
		if err := copyFile(sourceBootstrap, targetBootstrap); err != nil {
			return errors.Wrap(err, "copy bootstrap")
		}
	}

	targetBootstrapFile, err := os.OpenFile(targetBootstrap, os.O_RDWR, 0755)
	if err != nil {
		return errors.Wrap(err, "open target bootstrap")
	}
	defer targetBootstrapFile.Close()

	_, err = targetBootstrapFile.Seek(int64(sb.BlobTableOffset), io.SeekStart)
	if err != nil {
		return errors.Wrap(err, "seek blob table offset")
	}
	_, err = targetBootstrapFile.Write(blobTableBytes)
	if err != nil {
		return errors.Wrap(err, "write blob table for target bootstrap")
	}

	return nil
}

func replaceFileInTarGz(workDir string, srcTarGzReader io.Reader, destTarGz, oldFileName, newFilePath string) error {
	tmpDir, err := os.MkdirTemp(workDir, "replace-tar-gz")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	gzr, err := gzip.NewReader(srcTarGzReader)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Name == oldFileName {
			filePath := filepath.Join(tmpDir, header.Name)
			if err := copyFile(newFilePath, filePath); err != nil {
				return err
			}
			continue
		}

		filePath := filepath.Join(tmpDir, header.Name)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return err
		}
		outFile, err := os.Create(filePath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		if _, err := io.Copy(outFile, tr); err != nil {
			return err
		}
	}

	writer, err := os.Create(destTarGz)
	if err != nil {
		return err
	}
	defer writer.Close()

	gw := gzip.NewWriter(writer)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		header.Name = path[len(tmpDir)+1:]

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return err
			}
		}
		return nil
	})

	return err
}
