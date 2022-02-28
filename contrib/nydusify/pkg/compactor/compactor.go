package compactor

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
	"github.com/pkg/errors"
)

var defaultCompactConfig = &CompactConfig{
	MinUsedRatio:    5,
	CompactBlobSize: 10485760,
	MaxCompactSize:  104857600,
	LayersToCompact: 32,
}

type CompactConfig struct {
	MinUsedRatio    int    `json:"min_used_ratio"`
	CompactBlobSize int    `json:"compact_blob_size"`
	MaxCompactSize  int    `json:"max_compact_size"`
	LayersToCompact int    `json:"layers_to_compact"`
	BlobsDir        string `json:"blobs_dir,omitempty"`
}

func (cfg *CompactConfig) Dumps(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrap(err, "open file failed")
	}
	defer file.Close()
	if err = json.NewEncoder(file).Encode(cfg); err != nil {
		return errors.Wrap(err, "encode json failed")
	}
	return nil
}

func loadCompactConfig(filePath string) (CompactConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return CompactConfig{}, errors.Wrap(err, "load compact config file failed")
	}
	defer file.Close()
	var cfg CompactConfig
	if err = json.NewDecoder(file).Decode(&cfg); err != nil {
		return CompactConfig{}, errors.Wrap(err, "decode compact config file failed")
	}
	return cfg, nil
}

type Compactor struct {
	builder *build.Builder
	workdir string
	cfg     CompactConfig
}

func NewCompactor(nydusImagePath, workdir, configPath string) (*Compactor, error) {
	var (
		cfg CompactConfig
		err error
	)
	if configPath != "" {
		cfg, err = loadCompactConfig(configPath)
		if err != nil {
			return nil, errors.Wrap(err, "compact config err")
		}
	} else {
		cfg = *defaultCompactConfig
	}
	cfg.BlobsDir = workdir
	return &Compactor{
		builder: build.NewBuilder(nydusImagePath),
		workdir: workdir,
		cfg:     cfg,
	}, nil
}

func (compactor *Compactor) Compact(bootstrapPath, chunkDict, backendType, backendConfigFile string) (string, error) {
	targetBootstrap := bootstrapPath + ".compact"
	if err := os.Remove(targetBootstrap); err != nil && !os.IsNotExist(err) {
		return "", errors.Wrap(err, "delete old target bootstrap failed")
	}
	// prepare config file
	configFilePath := filepath.Join(compactor.workdir, "compact.json")
	if err := compactor.cfg.Dumps(configFilePath); err != nil {
		return "", errors.Wrap(err, "compact err")
	}
	outputJSONPath := filepath.Join(compactor.workdir, "compact-result.json")
	if err := os.Remove(outputJSONPath); err != nil && !os.IsNotExist(err) {
		return "", errors.Wrap(err, "delete old output-json file failed")
	}
	err := compactor.builder.Compact(build.CompactOption{
		ChunkDict:           chunkDict,
		BootstrapPath:       bootstrapPath,
		OutputBootstrapPath: targetBootstrap,
		BackendType:         backendType,
		BackendConfigPath:   backendConfigFile,
		OutputJSONPath:      outputJSONPath,
		CompactConfigPath:   configFilePath,
	})
	if err != nil {
		return "", errors.Wrap(err, "run compact command failed")
	}

	return targetBootstrap, nil
}
