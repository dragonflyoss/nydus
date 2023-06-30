package generator

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

// Opt defines Chunkdict generate options.
// Note: sources is one or more Nydus image references.
type Opt struct {
	WorkDir        string
	Sources        []string
	SourceInsecure bool
	NydusImagePath string
	ExpectedArch   string
}

// "Chunkdict generate" command generate chunkdict by deduplicating multiple nydus images
// by invoking "nydus-image chunkdict save" command to save chunk and blob information image into database.
// and by invoking "nydus-image chunkdict generate" to perform a deduplication algorithm from information of database to chunkdict
type Generator struct {
	Opt
	sourcesParser []*parser.Parser
}

// New creates Generator instance, sourceSlice is multiple Nydus images reference list.
func New(opt Opt) (*Generator, error) {
	// TODO: support sources resolver
	var sourcesParser []*parser.Parser
	for _, source := range opt.Sources {
		sourcesRemote, err := provider.DefaultRemote(source, opt.SourceInsecure)
		if err != nil {
			return nil, errors.Wrap(err, "Init source image parser")
		}
		sourceParser, err := parser.New(sourcesRemote, opt.ExpectedArch)
		sourcesParser = append(sourcesParser, sourceParser)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create parser")
		}
	}

	generator := &Generator{
		Opt:           opt,
		sourcesParser: sourcesParser,
	}

	return generator, nil
}

// "Chunkdict Generate" deposit multiple Nydus images into the database one by one.
func (generator *Generator) Generate(ctx context.Context) error {
	for index := range generator.Sources {
		if err := generator.save(ctx, index); err != nil {
			if utils.RetryWithHTTP(err) {
				generator.sourcesParser[index].Remote.MaybeWithHTTP(err)
			}
			if err := generator.save(ctx, index); err != nil {
				return err
			}
		}
	}
	return nil
}

// "Save" function stores information of chunk and blob of a Nydus Image in the database
func (generator *Generator) save(ctx context.Context, index int) error {
	sourceParsed, err := generator.sourcesParser[index].Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse Nydus image")
	}

	// Create a directory to store the image bootstrap
	nydusImageName := strings.Replace(generator.Sources[index], "/", ":", -1)
	folderPath := filepath.Join(generator.WorkDir, nydusImageName)
	if err := os.MkdirAll(folderPath, fs.ModePerm); err != nil {
		return errors.Wrap(err, "creat work directory")
	}

	logrus.Infof("Bootstrap path is %s", folderPath)

	if err := generator.Output(ctx, sourceParsed, folderPath, index); err != nil {
		return errors.Wrap(err, "output image information")
	}

	bootstrap := Bootstrap{
		NydusImagePath: generator.NydusImagePath,
		BootstrapPath:  filepath.Join(folderPath, "nydus_bootstrap"),
	}
	if err := bootstrap.Save(); err != nil {
		return errors.Wrapf(err, "validate rule %s", bootstrap.Name())
	}
	logrus.Infof("Chunkdict successfully save Nydus image %s", generator.sourcesParser[index].Remote.Ref)
	if err := os.RemoveAll(folderPath); err != nil {
		return errors.Wrap(err, "remove work directory")
	}
	return nil
}
