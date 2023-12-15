package packer

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

type Artifact struct {
	OutputDir string
}

func NewArtifact(outputDir string) (Artifact, error) {
	res := Artifact{OutputDir: outputDir}
	if err := res.ensureOutputDir(); err != nil {
		return Artifact{}, err
	}
	return res, nil
}

func (a Artifact) bootstrapPath(imageName string) string {
	if filepath.Ext(imageName) != "" {
		return filepath.Join(a.OutputDir, imageName)
	}
	return filepath.Join(a.OutputDir, imageName+".meta")
}

func (a Artifact) blobFilePath(imageName string, isDigest bool) string {
	if isDigest {
		return filepath.Join(a.OutputDir, imageName)
	} else if suffix := filepath.Ext(imageName); suffix != "" {
		return filepath.Join(a.OutputDir, strings.TrimSuffix(imageName, suffix)+".blob")
	} else {
		return filepath.Join(a.OutputDir, imageName+".blob")
	}
}

func (a Artifact) outputJSONPath() string {
	return filepath.Join(a.OutputDir, "output.json")
}

// ensureOutputDir use user defined outputDir or defaultOutputDir, and make sure dir exists
func (a *Artifact) ensureOutputDir() error {
	if utils.IsEmptyString(a.OutputDir) {
		a.OutputDir = defaultOutputDir
	}
	return os.MkdirAll(a.OutputDir, 0755)
}
