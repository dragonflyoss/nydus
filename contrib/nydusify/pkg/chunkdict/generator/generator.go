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
	if err := generator.deduplicating(ctx); err != nil {
		return err
	}
	return nil
}

// "save" stores information of chunk and blob of a Nydus Image in the database
func (generator *Generator) save(ctx context.Context, index int) error {
	currentDir, _ := os.Getwd()
	sourceParsed, err := generator.sourcesParser[index].Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse Nydus image")
	}

	// Create a directory to store the image bootstrap
	nydusImageName := strings.Replace(generator.Sources[index], "/", ":", -1)
	bootstrapFolderPath := filepath.Join(currentDir, generator.WorkDir, nydusImageName)
	if err := os.MkdirAll(bootstrapFolderPath, fs.ModePerm); err != nil {
		return errors.Wrap(err, "creat work directory")
	}
	if err := generator.Output(ctx, sourceParsed, bootstrapFolderPath, index); err != nil {
		return errors.Wrap(err, "output image information")
	}

	databaseName := "chunkdict.db"
	databaseType := "sqlite"
	DatabasePath := databaseType + "://" + filepath.Join(currentDir, generator.WorkDir, databaseName)

	// Invoke "nydus-image save" command
	builder := build.NewBuilder(generator.NydusImagePath)
	if err := builder.Save(build.SaveOption{
		BootstrapPath: filepath.Join(bootstrapFolderPath, "nydus_bootstrap"),
		DatabasePath:  DatabasePath,
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}

	logrus.Infof("Saving chunk information from image %s", generator.sourcesParser[index].Remote.Ref)

	// if err := os.RemoveAll(folderPath); err != nil {
	// 	return errors.Wrap(err, "remove work directory")
	// }
	return nil
}

func (generator *Generator) deduplicating(ctx context.Context) error {
	builder := build.NewBuilder(generator.NydusImagePath)
	currentDir, _ := os.Getwd()

	databaseName := "chunkdict.db"
	databaseType := "sqlite"
	DatabasePath := databaseType + "://" + filepath.Join(currentDir, generator.WorkDir, databaseName)
	if err := builder.Generate(build.GenerateOption{
		DatabasePath: DatabasePath,
	}); err != nil {
		return errors.Wrap(err, "invalid nydus bootstrap format")
	}
	return nil
}
