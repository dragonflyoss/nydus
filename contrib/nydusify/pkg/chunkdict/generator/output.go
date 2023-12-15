package generator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func prettyDump(obj interface{}, name string) error {
	bytes, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(name, bytes, 0644)
}

// Output outputs Nydus image nydus_bootstrap file and manifest, config to JSON file.
func (generator *Generator) Output(
	ctx context.Context, sourceParsed *parser.Parsed, outputPath string, index int,
) error {
	if sourceParsed.Index != nil {
		if err := prettyDump(
			sourceParsed.Index,
			filepath.Join(outputPath, "nydus_index.json"),
		); err != nil {
			return errors.Wrap(err, "output nydus index file")
		}
	}
	if sourceParsed.NydusImage != nil {
		if err := prettyDump(
			sourceParsed.NydusImage.Manifest,
			filepath.Join(outputPath, "nydus_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus manifest file")
		}
		if err := prettyDump(
			sourceParsed.NydusImage.Config,
			filepath.Join(outputPath, "nydus_config.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus config file")
		}
		source := filepath.Join(outputPath, "nydus_bootstrap")
		logrus.Infof("Pulling Nydus bootstrap to %s", source)
		bootstrapReader, err := generator.sourcesParser[index].PullNydusBootstrap(ctx, sourceParsed.NydusImage)
		if err != nil {
			return errors.Wrap(err, "pull Nydus bootstrap layer")
		}
		defer bootstrapReader.Close()

		if err := utils.UnpackFile(bootstrapReader, utils.BootstrapFileNameInLayer, source); err != nil {
			return errors.Wrap(err, "unpack Nydus bootstrap layer")
		}
	} else {
		err := fmt.Errorf("the %s is not a Nydus image", generator.sourcesParser[index].Remote.Ref)
		return err
	}
	return nil
}
