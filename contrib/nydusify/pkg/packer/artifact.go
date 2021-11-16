package packer

import (
	"os"
	"path/filepath"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
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

func (a Artifact) bootstrapPath(metaFileName string) string {
	return filepath.Join(a.OutputDir, metaFileName)
}

func (a Artifact) outputJsonPath() string {
	return filepath.Join(a.OutputDir, "output.json")
}

func (a Artifact) blobFilePath(blobFileName string) string {
	return filepath.Join(a.OutputDir, blobFileName)
}

// ensureOutputDir use user defined outputDir or defaultOutputDir, and make sure dir exists
func (a *Artifact) ensureOutputDir() error {
	if utils.IsEmptyString(a.OutputDir) {
		a.OutputDir = defaultOutputDir
	}
	return os.MkdirAll(a.OutputDir, 0755)
}
