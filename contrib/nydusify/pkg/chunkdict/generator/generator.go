package generator

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/build"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
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

// Generator generates chunkdict by deduplicating multiple nydus images
// invoking "nydus-image chunkdict save" to save image information into database.
type Generator struct {
	Opt
	sourcesParser []*parser.Parser
}

// New creates Generator instance.
func New(opt Opt) (*Generator, error) {
	// TODO: support sources image resolver
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

// Generate saves multiple Nydus bootstraps into the database one by one.
func (generator *Generator) Generate(ctx context.Context) error {
	var bootstrapPaths []string
	bootstrapPaths, err := generator.pull(ctx)

	if err != nil {
		if utils.RetryWithHTTP(err) {
			for index := range generator.Sources {
				generator.sourcesParser[index].Remote.MaybeWithHTTP(err)
			}
		}
		bootstrapPaths, err = generator.pull(ctx)
		if err != nil {
			return err
		}
	}

	if err := generator.generate(ctx, bootstrapPaths); err != nil {
		return err
	}
	return nil
}

// Pull the bootstrap of nydus image
func (generator *Generator) pull(ctx context.Context) ([]string, error) {
	var bootstrapPaths []string
	for index := range generator.Sources {
		sourceParsed, err := generator.sourcesParser[index].Parse(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "parse Nydus image")
		}

		// Create a directory to store the image bootstrap
		nydusImageName := strings.Replace(generator.Sources[index], "/", ":", -1)
		bootstrapDirPath := filepath.Join(generator.WorkDir, nydusImageName)
		if err := os.MkdirAll(bootstrapDirPath, fs.ModePerm); err != nil {
			return nil, errors.Wrap(err, "creat work directory")
		}
		if err := generator.Output(ctx, sourceParsed, bootstrapDirPath, index); err != nil {
			return nil, errors.Wrap(err, "output image information")
		}
		bootstrapPath := filepath.Join(bootstrapDirPath, "nydus_bootstrap")
		bootstrapPaths = append(bootstrapPaths, bootstrapPath)
	}
	return bootstrapPaths, nil
}

func (generator *Generator) generate(ctx context.Context, bootstrapPaths []string) error {
	// Invoke "nydus-image generate" command
	currentDir, _ := os.Getwd()
	builder := build.NewBuilder(generator.NydusImagePath)
	databaseType := "sqlite"
	var databasePath string
	if strings.HasPrefix(generator.WorkDir, "/") {
		databasePath = databaseType + "://" + filepath.Join(generator.WorkDir, "database.db")
	} else {
		databasePath = databaseType + "://" + filepath.Join(currentDir, generator.WorkDir, "database.db")
	}
	if err := builder.Generate(build.GenerateOption{
		BootstrapPaths:         bootstrapPaths,
		ChunkdictBootstrapPath: filepath.Join(generator.WorkDir, "chunkdict_bootstrap"),
		DatabasePath:           databasePath,
		OutputPath:             filepath.Join(generator.WorkDir, "nydus_bootstrap_output.json"),
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}

	logrus.Infof("Successfully generate image chunk dictionary")

	return nil
}
