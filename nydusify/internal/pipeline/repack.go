package pipeline

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type repackReport struct {
	Version   int      `json:"version"`
	Phase     string   `json:"phase"`
	Pruned    bool     `json:"pruned"`
	Compacted bool     `json:"compacted"`
	Blobs     []string `json:"blobs"`
	refs      map[digest.Digest]struct{}
}

func (r *repackReport) references() (map[digest.Digest]struct{}, error) {
	if r.refs != nil {
		return r.refs, nil
	}
	refs := make(map[digest.Digest]struct{}, len(r.Blobs))
	for _, id := range r.Blobs {
		dgst := digest.NewDigestFromEncoded(digest.SHA256, id)
		if err := dgst.Validate(); err != nil {
			return nil, errors.Wrap(err, "invalid repack blob digest")
		}
		if _, ok := refs[dgst]; ok {
			return nil, errors.Errorf("duplicate repack blob digest %s", dgst)
		}
		refs[dgst] = struct{}{}
	}
	r.refs = refs
	return refs, nil
}

var runArtifactRepack = executeArtifactRepack

// One child process retains the parsed bootstrap across the preparation callback.
func executeArtifactRepack(ctx context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (result repackReport, err error) {
	args := []string{"repack", "--bootstrap", opt.BootstrapPath, "--blob-dir", blobs,
		"--output-dir", output, "--compact-max-layers", fmt.Sprint(opt.CompactMaxLayers),
		"--compressor", cmp.Or(opt.CompactCompressor, nydus.DefaultCompressor), "--prepare-stdio"}
	if opt.repackConfig != "" {
		args = append(args, "--config", opt.repackConfig)
	}
	if opt.Prune {
		args = append(args, "--prune")
	}
	cmd := exec.CommandContext(ctx, cmp.Or(opt.BuilderPath, nydus.DefaultBuilder), args...)
	nydus.DieWithParent(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return result, err
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return result, err
	}
	if err := cmd.Start(); err != nil {
		return result, err
	}
	waited := false
	defer func() {
		_ = in.Close()
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if err != nil {
			err = errors.Wrapf(err, "repack artifacts: %s", stderr.String())
		}
	}()
	decoder := json.NewDecoder(out)
	var plan repackReport
	if err = decoder.Decode(&plan); err != nil {
		return result, errors.Wrap(err, "read repack plan")
	}
	if plan.Version != 1 || plan.Phase != "plan" {
		return result, errors.New("invalid repack plan version or phase")
	}
	if _, err = plan.references(); err != nil {
		return result, err
	}
	if err = prepare(plan); err != nil {
		return result, err
	}
	if _, err = io.WriteString(in, "ready\n"); err != nil {
		return result, err
	}
	_ = in.Close()
	if err = decoder.Decode(&result); err != nil {
		return result, errors.Wrap(err, "read repack result")
	}
	// Drain stdout so a malformed child cannot leave Wait blocked on its pipe.
	if _, err = io.Copy(io.Discard, out); err != nil {
		return result, err
	}
	waited = true
	if err = cmd.Wait(); err != nil {
		return result, err
	}
	if result.Version != 1 || result.Phase != "result" || result.Pruned != plan.Pruned || result.Compacted != plan.Compacted {
		return result, errors.New("repack result does not match preparation plan")
	}
	if _, err = result.references(); err != nil {
		return result, err
	}
	if !result.Compacted && !slices.Equal(result.Blobs, plan.Blobs) {
		return result, errors.New("prune changed planned source blob identities")
	}
	result.refs = nil
	return result, nil
}

func repackArtifact(ctx context.Context, opt ArtifactOption, sourceBlobCount int, prepare func(repackReport, string) error) (report repackReport, work string, err error) {
	switch opt.CompactCompressor {
	case "", "none", "zstd", "lz4":
	default:
		return report, "", errors.Errorf("unsupported compact compressor %q", opt.CompactCompressor)
	}
	if opt.WorkDir == "" {
		return report, "", errors.New("repack requires a work directory")
	}
	if err := os.MkdirAll(opt.WorkDir, 0700); err != nil {
		return report, "", err
	}
	work, err = os.MkdirTemp(opt.WorkDir, "repack-")
	if err != nil {
		return report, "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(work)
		}
	}()
	blobs := filepath.Join(work, "blobs")
	if err = os.Mkdir(blobs, 0700); err != nil {
		return report, work, err
	}
	if opt.OpenCompactBlob != nil && opt.CompactMaxLayers > 0 &&
		len(opt.ParentImages) > 0 && uint(sourceBlobCount) > opt.CompactMaxLayers {
		config, closeBackend, startErr := startRepackBackend(ctx, opt, blobs, work)
		if startErr != nil {
			return report, work, startErr
		}
		defer closeBackend()
		opt.repackConfig = config
	}
	output := filepath.Join(work, "output")
	report, err = runArtifactRepack(ctx, opt, blobs, output, func(plan repackReport) error {
		return prepare(plan, blobs)
	})
	if err != nil {
		return report, work, err
	}
	for _, dir := range []string{blobs, filepath.Join(output, "cache"), opt.repackConfig} {
		if dir == "" {
			continue
		}
		if err = os.RemoveAll(dir); err != nil {
			return report, work, err
		}
	}
	success = true
	return report, work, nil
}

func stageRepackBlobs(opt ArtifactOption, descs []ocispec.Descriptor, paths map[digest.Digest]string, blobs string, metas []nydus.BlobMetaFile) error {
	for _, desc := range descs {
		dest := filepath.Join(blobs, desc.Digest.Encoded())
		var err error
		if path, ok := paths[desc.Digest]; ok {
			path, err = filepath.Abs(path)
			if err == nil {
				err = os.Symlink(path, dest)
			}
		} else if opt.OpenCompactBlob == nil {
			err = errors.Errorf("compact needs data for blob %s", desc.Digest)
		} else {
			// Publish a descriptor, not a full downloaded data blob.
			var data []byte
			data, err = json.Marshal(desc)
			if err == nil {
				err = os.WriteFile(dest+".descriptor.json", data, 0600)
			}
		}
		if err != nil {
			return errors.Wrapf(err, "prepare compact blob %s", desc.Digest)
		}
	}
	if len(metas) > 0 {
		cache := filepath.Join(filepath.Dir(blobs), "output", "cache")
		if err := os.MkdirAll(cache, 0700); err != nil {
			return err
		}
		live := make(map[string]struct{}, len(descs))
		for _, desc := range descs {
			live[desc.Digest.Encoded()+".blob.meta"] = struct{}{}
		}
		for _, meta := range metas {
			if _, ok := live[meta.Name]; !ok {
				continue
			}
			if err := os.WriteFile(filepath.Join(cache, meta.Name), meta.Data, 0600); err != nil {
				return errors.Wrapf(err, "stage compact metadata %s", meta.Name)
			}
		}
	}
	return nil
}
