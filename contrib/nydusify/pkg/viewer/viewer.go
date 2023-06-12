package viewer

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

func prettyDump(obj interface{}, name string) error {
	bytes, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(name, bytes, 0644)
}

// Opt defines fsViewer options, Target is the Nydus image reference
type Opt struct {
	WorkDir        string
	Target         string
	TargetInsecure bool

	MountPath     string
	NydusdPath    string
	BackendType   string
	BackendConfig string
	ExpectedArch  string
	FsVersion     string
}

// fsViewer provides complete view of file system in nydus image
type FsViewer struct {
	Opt
	Parser       *parser.Parser
	NydusdConfig tool.NydusdConfig
}

// New creates fsViewer instance, Target is the Nydus image reference
func New(opt Opt) (*FsViewer, error) {
	if opt.Target == "" {
		return nil, errors.Errorf("missing target image reference, please add option '--target reference'")
	}
	targetRemote, err := provider.DefaultRemote(opt.Target, opt.TargetInsecure)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create image provider")
	}
	targetParser, err := parser.New(targetRemote, opt.ExpectedArch)
	if targetParser == nil {
		return nil, errors.Wrap(err, "failed to create image reference parser")
	}

	mode := "cached"
	digestValidate := false
	if opt.FsVersion == "6" {
		mode = "direct"
		digestValidate = false
	}
	// targetParsed, err := targetParser.Parse()
	// if err != nil {
	// 	return errors.Wrap(err, "parse Nydus image")
	// }

	// digestValidate := false
	// if targetParsed.NydusImage != nil {
	// 	nydusManifest := parser.FindNydusBootstrapDesc(&targetParsed.NydusImage.Manifest)
	// 	if nydusManifest != nil {
	// 		v := utils.GetNydusFsVersionOrDefault(nydusManifest.Annotations, utils.V5)
	// 		if v == utils.V5 {
	// 			// Digest validate is not currently supported for v6,
	// 			// but v5 supports it. In order to make the check more sufficient,
	// 			// this validate needs to be turned on for v5.
	// 			digestValidate = true
	// 		}
	// 	}
	// }

	nydusdConfig := tool.NydusdConfig{
		NydusdPath:     opt.NydusdPath,
		BackendType:    opt.BackendType,
		BackendConfig:  opt.BackendConfig,
		BootstrapPath:  filepath.Join(opt.WorkDir, "nydus_bootstrap"),
		ConfigPath:     filepath.Join(opt.WorkDir, "fs/nydusd_config.json"),
		BlobCacheDir:   filepath.Join(opt.WorkDir, "fs/nydus_blobs"),
		MountPath:      opt.MountPath,
		APISockPath:    filepath.Join(opt.WorkDir, "fs/nydus_api.sock"),
		Mode:           mode,
		DigestValidate: digestValidate,
	}

	fsViewer := &FsViewer{
		Opt:          opt,
		Parser:       targetParser,
		NydusdConfig: nydusdConfig,
	}

	return fsViewer, nil
}

// Pull Bootstrap, includes nydus_manifest.json and nydus_config.json
func (fsViewer *FsViewer) PullBootstrap(ctx context.Context, targetParsed *parser.Parsed) error {
	if err := os.RemoveAll(fsViewer.WorkDir); err != nil {
		return errors.Wrap(err, "failed to clean up working directory")
	}

	if err := os.MkdirAll(filepath.Join(fsViewer.WorkDir, "fs"), 0750); err != nil {
		return errors.Wrap(err, "can't create working directory")
	}

	if targetParsed.NydusImage != nil {
		if err := prettyDump(
			targetParsed.NydusImage.Manifest,
			filepath.Join(fsViewer.WorkDir, "nydus_manifest.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus manifest file")
		}
		if err := prettyDump(
			targetParsed.NydusImage.Config,
			filepath.Join(fsViewer.WorkDir, "nydus_config.json"),
		); err != nil {
			return errors.Wrap(err, "output Nydus config file")
		}

		target := filepath.Join(fsViewer.WorkDir, "nydus_bootstrap")
		logrus.Infof("Pulling Nydus bootstrap to %s", target)
		bootstrapReader, err := fsViewer.Parser.PullNydusBootstrap(ctx, targetParsed.NydusImage)
		if err != nil {
			return errors.Wrap(err, "failed to pull Nydus bootstrap layer")
		}
		defer bootstrapReader.Close()

		if err := utils.UnpackFile(bootstrapReader, utils.BootstrapFileNameInLayer, target); err != nil {
			return errors.Wrap(err, "failed to unpack Nydus bootstrap layer")
		}
	}

	return nil
}

// Mount nydus image.
func (fsViewer *FsViewer) MountImage() error {
	logrus.Infof("Mounting Nydus image to %s", fsViewer.NydusdConfig.MountPath)

	if err := os.MkdirAll(fsViewer.NydusdConfig.BlobCacheDir, 0750); err != nil {
		return errors.Wrap(err, "can't create blob cache directory for Nydusd")
	}

	if err := os.MkdirAll(fsViewer.NydusdConfig.MountPath, 0750); err != nil {
		return errors.Wrap(err, "can't create mountpoint directory of Nydus image")
	}

	nydusd, err := tool.NewNydusd(fsViewer.NydusdConfig)
	if err != nil {
		return errors.Wrap(err, "can't create Nydusd daemon")
	}

	if err := nydusd.Mount(); err != nil {
		return errors.Wrap(err, "failed to mount Nydus image")
	}

	return nil
}

// View provides the structure of the file system in target nydus image
// It includes two steps, pull the boostrap of the image, and mount the
// image under specified path.
func (fsViewer *FsViewer) View(ctx context.Context) error {
	if err := fsViewer.view(ctx); err != nil {
		if utils.RetryWithHTTP(err) {
			fsViewer.Parser.Remote.MaybeWithHTTP(err)
			return fsViewer.view(ctx)
		}
		return err

	}
	return nil
}

func (fsViewer *FsViewer) view(ctx context.Context) error {
	// Pull bootstrap
	targetParsed, err := fsViewer.Parser.Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to parse image reference")
	}
	err = fsViewer.PullBootstrap(ctx, targetParsed)
	if err != nil {
		return errors.Wrap(err, "failed to pull Nydus image bootstrap")
	}

	//Adjust nydused parameters(DigestValidate) according to rafs format
	nydusManifest := parser.FindNydusBootstrapDesc(&targetParsed.NydusImage.Manifest)
	if nydusManifest != nil {
		v := utils.GetNydusFsVersionOrDefault(nydusManifest.Annotations, utils.V5)
		if v == utils.V5 {
			// Digest validate is not currently supported for v6,
			// but v5 supports it. In order to make the check more sufficient,
			// this validate needs to be turned on for v5.
			fsViewer.NydusdConfig.DigestValidate = true
		}
	}

	err = fsViewer.MountImage()
	if err != nil {
		return err
	}

	// Block current goroutine in order to umount the file system and clean up workdir
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		logrus.Infof("Received Signal: %s", sig)
		done <- true
	}()

	logrus.Infof("Please send signal SIGINT/SIGTERM to umount the file system")
	<-done
	if err := os.RemoveAll(fsViewer.WorkDir); err != nil {
		return errors.Wrap(err, "failed to clean up working directory")
	}

	return nil
}
