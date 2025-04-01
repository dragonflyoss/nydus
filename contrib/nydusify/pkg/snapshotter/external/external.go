package external

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Dir              string
	ContextDir       string
	Handler          backend.Handler
	RemoteHandler    backend.RemoteHanlder
	MetaOutput       string
	BackendOutput    string
	AttributesOutput string
}

type Attribute struct {
	Pattern string
}

// Handle handles the directory and generates the backend meta and attributes.
func Handle(ctx context.Context, opts Options) error {
	walker := backend.NewWalker()

	backendRet, err := walker.Walk(ctx, opts.Dir, opts.Handler)
	if err != nil {
		return err
	}
	generators, err := NewGenerators(*backendRet)
	if err != nil {
		return err
	}
	ret, err := generators.Generate()
	if err != nil {
		return err
	}
	bkd := ret.Backend
	attributes := buildAttr(ret)

	if err := os.WriteFile(opts.MetaOutput, ret.Meta, 0644); err != nil {
		return errors.Wrapf(err, "write meta to %s", opts.MetaOutput)
	}

	backendBytes, err := json.MarshalIndent(bkd, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.BackendOutput, backendBytes, 0644); err != nil {
		return errors.Wrapf(err, "write backend json to %s", opts.BackendOutput)
	}
	logrus.Debugf("backend json: %s", backendBytes)

	attributeContent := []string{}
	for _, attribute := range attributes {
		attributeContent = append(attributeContent, attribute.Pattern)
	}
	if err := os.WriteFile(opts.AttributesOutput, []byte(strings.Join(attributeContent, "\n")), 0644); err != nil {
		return errors.Wrapf(err, "write attributes to %s", opts.AttributesOutput)
	}
	logrus.Debugf("attributes: %v", strings.Join(attributeContent, "\n"))

	return nil
}

func buildAttr(ret *Result) []Attribute {
	attributes := []Attribute{}
	for _, file := range ret.Files {
		p := fmt.Sprintf("/%s type=%s blob_index=%d blob_id=%s chunk_size=%s chunk_0_compressed_offset=%d compressed_size=%s",
			file.RelativePath, file.Type, file.BlobIndex, file.BlobID, file.ChunkSize, file.Chunk0CompressedOffset, file.BlobSize)
		attributes = append(attributes, Attribute{
			Pattern: p,
		})
	}
	return attributes
}

func RemoteHandle(ctx context.Context, opts Options) error {
	bkd, fileAttrs, err := opts.RemoteHandler.Handle(ctx)
	if err != nil {
		return errors.Wrap(err, "handle modctl")
	}
	attributes := []Attribute{}
	for _, file := range fileAttrs {
		p := fmt.Sprintf("/%s type=%s file_size=%d blob_index=%d blob_id=%s chunk_size=%s chunk_0_compressed_offset=%d compressed_size=%s",
			file.RelativePath, file.Type, file.FileSize, file.BlobIndex, file.BlobID, file.ChunkSize, file.Chunk0CompressedOffset, file.BlobSize)
		attributes = append(attributes, Attribute{
			Pattern: p,
		})
		logrus.Infof("file attr: %s, file_mode: %o", p, file.Mode)
	}

	backendBytes, err := json.MarshalIndent(bkd, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.BackendOutput, backendBytes, 0644); err != nil {
		return errors.Wrapf(err, "write backend json to %s", opts.BackendOutput)
	}
	logrus.Debugf("backend json: %s", backendBytes)

	attributeContent := []string{}
	for _, attribute := range attributes {
		attributeContent = append(attributeContent, attribute.Pattern)
	}
	if err := os.WriteFile(opts.AttributesOutput, []byte(strings.Join(attributeContent, "\n")), 0644); err != nil {
		return errors.Wrapf(err, "write attributes to %s", opts.AttributesOutput)
	}
	logrus.Debugf("attributes: %v", strings.Join(attributeContent, "\n"))

	// Build dummy files with empty content.
	if err := buildEmptyFiles(fileAttrs, opts.ContextDir); err != nil {
		return errors.Wrap(err, "build empty files")
	}

	return nil
}

func buildEmptyFiles(fileAttrs []backend.FileAttribute, contextDir string) error {
	for _, fileAttr := range fileAttrs {
		filePath := fmt.Sprintf("%s/%s", contextDir, fileAttr.RelativePath)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return errors.Wrapf(err, "create dir %s", filepath.Dir(filePath))
		}
		if err := os.WriteFile(filePath, []byte{}, os.FileMode(fileAttr.Mode)); err != nil {
			return errors.Wrapf(err, "write file %s", filePath)
		}
	}
	return nil
}
