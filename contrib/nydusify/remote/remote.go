// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/containerd/containerd/remotes/docker/config"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"contrib/nydusify/signature"
)

const (
	ManifestOSFeatureNydus        = "nydus.remoteimage.v1"
	MediaTypeNydusBlob            = "application/vnd.oci.image.layer.nydus.blob.v1"
	LayerAnnotationNydusBlob      = "containerd.io/snapshot/nydus-blob"
	LayerAnnotationNydusBootstrap = "containerd.io/snapshot/nydus-bootstrap"
	LayerAnnotationNydusSignature = "containerd.io/snapshot/nydus-signature"
	BootstrapFileNameInLayer      = "image.boot"
)

// Manifest from OCI spec
type Manifest struct {
	ocispec.Manifest
	MediaType string `json:"mediaType"`
}

// ManifestIndex from OCI spec
type ManifestIndex struct {
	ocispec.Index
	MediaType string `json:"mediaType"`
}

// Remote hold all image info during convertion workflow
type Remote struct {
	source string
	target string

	ctx          context.Context
	client       *containerd.Client
	pullResolver remotes.Resolver
	pushResolver remotes.Resolver
	lease        leases.Lease

	sourceImage        containerd.Image
	sourceConfig       ocispec.Image
	sourceManifest     *ocispec.Manifest
	sourceManifestDesc *ocispec.Descriptor

	targetConfigDesc   *ocispec.Descriptor
	targetManifestDesc *ocispec.Descriptor
	targetLayers       []ocispec.Descriptor
	targetSignature    []byte
}

// Option for remote
type Option struct {
	ContainerdSock string
	Source         string
	Target         string
	SourceAuth     string
	TargetAuth     string
	SourceInsecure bool
	TargetInsecure bool
}

func createTar(filePath string, tarWriter io.Writer) error {
	tw := tar.NewWriter(tarWriter)
	defer tw.Close()

	fw, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
	if err != nil {
		return errors.Wrap(err, "open file for tar")
	}
	fi, err := fw.Stat()
	if err != nil {
		return errors.Wrap(err, "stat file for tar")
	}

	hdr := &tar.Header{
		Name: BootstrapFileNameInLayer,
		Mode: 0666,
		Size: fi.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.Wrap(err, "write header for tar")
	}

	if _, err := io.Copy(tw, fw); err != nil {
		return errors.Wrap(err, "taring file")
	}

	return nil
}

func signBootstrap(bootstrapPath, privateKeyPath string) ([]byte, error) {
	logrus.Infof("Signing bootstrap signature with private key")

	file, err := os.OpenFile(bootstrapPath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, errors.Wrap(err, "open bootstrap file")
	}

	return signature.Sign(privateKeyPath, file)
}

func newResolver(ctx context.Context, insecure bool, auth string) (remotes.Resolver, error) {
	username := ""
	password := ""

	if auth != "" {
		data, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, errors.Wrap(err, "decode auth string")
		}
		auths := strings.Split(string(data), ":")
		if len(auths) < 2 {
			return nil, errors.Wrap(err, "parse auth string")
		}
		username = auths[0]
		password = auths[1]
	}

	hostOptions := config.HostOptions{}
	hostOptions.Credentials = func(host string) (string, string, error) {
		return username, password, nil
	}
	if insecure {
		hostOptions.DefaultScheme = "http"
	}
	options := docker.ResolverOptions{
		Tracker: docker.NewInMemoryTracker(),
	}
	options.Hosts = config.ConfigureHosts(ctx, hostOptions)

	return docker.NewResolver(options), nil
}

func (remote *Remote) writeContentStore(data []byte) (int, *digest.Digest, error) {
	cs := remote.client.ContentStore()

	writer, err := cs.Writer(remote.ctx, content.WithRef("nydus"))
	if err != nil {
		return 0, nil, err
	}
	defer writer.Close()

	size, err := writer.Write(data)
	if err != nil {
		return 0, nil, err
	}
	digest := writer.Digest()

	if err := writer.Commit(remote.ctx, 0, ""); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return 0, nil, err
		}
	}

	return size, &digest, nil
}

// New connect containerd service and prepare source & target registry resolver
func New(option Option) (*Remote, error) {
	ctx := namespaces.WithNamespace(context.Background(), "nydus-image-converter")

	client, err := containerd.New(option.ContainerdSock)
	if err != nil {
		return nil, err
	}

	// Using containerd lease for content garbage collection
	manager := client.LeasesService()
	lease, err := manager.Create(ctx, leases.WithExpiration(time.Duration(time.Hour*24)))
	if err != nil {
		return nil, err
	}
	ctx = leases.WithLease(ctx, lease.ID)

	pullResolver, err := newResolver(ctx, option.SourceInsecure, option.SourceAuth)
	if err != nil {
		return nil, errors.Wrap(err, "configure source resolver")
	}

	pushResolver, err := newResolver(ctx, option.TargetInsecure, option.TargetAuth)
	if err != nil {
		return nil, errors.Wrap(err, "configure target resolver")
	}

	remote := Remote{
		ctx:          ctx,
		client:       client,
		pullResolver: pullResolver,
		pushResolver: pushResolver,
		source:       option.Source,
		target:       option.Target,
		lease:        lease,
	}

	return &remote, nil
}

// Clean tells containerd to release content resource
func (remote *Remote) Clean() error {
	if err := remote.client.LeasesService().Delete(remote.ctx, remote.lease); err != nil {
		return err
	}
	return nil
}

// Pull source image from source registry
// TODO: Starting to build layer as quickly as possible if we can capture layer pulled event.
func (remote *Remote) Pull() error {
	logrus.Infof("Pulling image %s with platform %s", remote.source, platforms.DefaultString())

	// Pull source image matching default platform
	image, err := remote.client.Pull(
		remote.ctx,
		remote.source,
		containerd.WithPullUnpack,
		containerd.WithResolver(remote.pullResolver),
		containerd.WithPlatformMatcher(platforms.Default()),
	)
	if err != nil {
		return errors.Wrap(err, "pull image")
	}

	// Get source image manifest descriptor matching default platform
	descs, err := images.Children(remote.ctx, remote.client.ContentStore(), image.Target())
	if err != nil {
		return err
	}
	platform := platforms.Default()
	var sourceManifestDesc *ocispec.Descriptor
	for _, desc := range descs {
		if desc.Platform == nil || platform.Match(*desc.Platform) {
			sourceManifestDesc = &desc
			break
		}
	}
	if sourceManifestDesc == nil {
		return errors.Wrap(err, "get image manifest descriptor")
	}

	// Get source image manifest matching default platform
	manifest, err := images.Manifest(remote.ctx, image.ContentStore(), image.Target(), platforms.Default())
	if err != nil {
		return errors.Wrap(err, "get image manifest")
	}

	// Get source image config
	configData, err := content.ReadBlob(remote.ctx, image.ContentStore(), manifest.Config)
	if err != nil {
		return errors.Wrap(err, "read config blob")
	}
	var config ocispec.Image
	if err := json.Unmarshal(configData, &config); err != nil {
		return errors.Wrap(err, "unmarshal image config")
	}

	remote.sourceConfig = config
	remote.sourceImage = image
	remote.sourceManifest = &manifest
	remote.sourceManifestDesc = sourceManifestDesc

	return nil
}

// Unpack layer tar file to directory and not ignore OCI whiteout file
func (remote *Remote) Unpack(workDir string, callback func(string) error) error {
	// Write manifest.json to source directory
	manifestFile := filepath.Join(workDir, remote.source, "manifest.json")
	manifest, err := json.Marshal(remote.sourceManifest)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(manifestFile, manifest, 0644); err != nil {
		return err
	}

	sourceDir := filepath.Join(workDir, remote.source)
	cs := remote.sourceImage.ContentStore()

	// TODO: skip to unpack if the layer has been unpacked
	for _, layer := range remote.sourceManifest.Layers {
		logrus.Infof("Unpacking layer %s", layer.Digest)

		ra, err := cs.ReaderAt(remote.ctx, layer)
		if err != nil {
			return err
		}
		cr := content.NewReader(ra)
		ds, err := compression.DecompressStream(cr)
		if err != nil {
			return err
		}
		defer ds.Close()

		layerDir := filepath.Join(sourceDir, layer.Digest.String())
		if err := os.MkdirAll(layerDir, 0666); err != nil {
			return err
		}

		convertWhiteout := func(hdr *tar.Header, file string) (bool, error) {
			return true, nil
		}

		if _, err := archive.Apply(remote.ctx, layerDir, ds, archive.WithConvertWhiteout(convertWhiteout)); err != nil {
			return errors.Wrap(err, "unpack layer")
		}

		if err := callback(layerDir); err != nil {
			return err
		}
	}

	return nil
}

// PushBlobLayer upload nydus blob file to target registry
// TODO: skip to write containerd content store if blob exists
func (remote *Remote) PushBlobLayer(blobPath string) error {
	blobID := filepath.Base(blobPath)
	blobDigest := digest.Digest(fmt.Sprintf("sha256:%s", blobID))

	logrus.Infof("Pushing blob layer %s", blobDigest)

	cs := remote.client.ContentStore()

	blobFile, err := os.OpenFile(blobPath, os.O_RDONLY, 0666)
	if err != nil {
		return errors.Wrap(err, "open blob file")
	}

	writer, err := cs.Writer(remote.ctx, content.WithRef(blobDigest.String()))
	if err != nil {
		return err
	}
	defer writer.Close()

	if _, err := io.Copy(writer, blobFile); err != nil {
		return err
	}

	if err := writer.Commit(remote.ctx, 0, ""); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return err
		}
	}

	info, err := cs.Info(remote.ctx, blobDigest)
	if err != nil {
		return err
	}

	desc := ocispec.Descriptor{
		MediaType: MediaTypeNydusBlob,
		Digest:    info.Digest,
		Size:      info.Size,
		Annotations: map[string]string{
			LayerAnnotationNydusBlob: "true",
		},
	}
	remote.targetLayers = append(remote.targetLayers, desc)

	if err := remote.client.Push(remote.ctx, remote.target, desc, containerd.WithResolver(remote.pushResolver)); err != nil {
		return errors.Wrap(err, "push blob layer")
	}

	return nil
}

// PushBoostrapLayer upload bootstrap file to target registry
// TODO: skip to write containerd content store if bootstrap exists
func (remote *Remote) PushBoostrapLayer(bootstrapPath, privateKeyPath string) error {
	cs := remote.client.ContentStore()

	layerAnnotations := map[string]string{
		LayerAnnotationNydusBootstrap: "true",
	}

	if strings.TrimSpace(privateKeyPath) != "" {
		signature, err := signBootstrap(bootstrapPath, privateKeyPath)
		if err != nil {
			return errors.Wrap(err, "sign bootstrap file")
		}
		layerAnnotations[LayerAnnotationNydusSignature] = string(signature)
	}

	writer, err := cs.Writer(remote.ctx, content.WithRef("nydus"))
	if err != nil {
		return err
	}
	defer writer.Close()

	if err := createTar(bootstrapPath, writer); err != nil {
		return errors.Wrap(err, "create bootstrap tar file")
	}

	digest := writer.Digest()
	if err != nil {
		return err
	}

	logrus.Infof("Pushing bootstrap layer %s", digest)

	if err := writer.Commit(remote.ctx, 0, ""); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return err
		}
	}

	info, err := cs.Info(remote.ctx, digest)
	if err != nil {
		return err
	}

	desc := ocispec.Descriptor{
		MediaType:   images.MediaTypeDockerSchema2Layer,
		Digest:      digest,
		Size:        info.Size,
		Annotations: layerAnnotations,
	}
	remote.targetLayers = append(remote.targetLayers, desc)

	if err := remote.client.Push(remote.ctx, remote.target, desc, containerd.WithResolver(remote.pushResolver)); err != nil {
		return errors.Wrap(err, "push bootstrap layer")
	}

	return nil
}

// PushConfig push target config to target registry
func (remote *Remote) PushConfig() error {
	config := remote.sourceConfig

	now := time.Now()
	config.Created = &now
	config.Author = "nydusify"
	config.RootFS.Type = "layers"

	config.RootFS.DiffIDs = []digest.Digest{}
	config.History = []ocispec.History{}
	for _, layer := range remote.targetLayers {
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, layer.Digest)
		config.History = append(config.History, ocispec.History{
			Created:   &now,
			CreatedBy: fmt.Sprintf("nydusify %s %s", remote.source, remote.target),
		})
	}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	size, digest, err := remote.writeContentStore(data)
	if err != nil {
		return err
	}

	configDesc := remote.sourceManifest.Config
	configDesc.Digest = *digest
	configDesc.Size = int64(size)

	if err := remote.client.Push(remote.ctx, remote.target, configDesc, containerd.WithResolver(remote.pushResolver)); err != nil {
		return errors.Wrap(err, "push image config")
	}

	remote.targetConfigDesc = &configDesc

	return nil
}

// PushManifest push target manifest to target registry
func (remote *Remote) PushManifest() error {
	logrus.Infof("Pushing nydus manifest")

	manifest := Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Manifest: ocispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Config: *remote.targetConfigDesc,
			Layers: remote.targetLayers,
		},
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	size, digest, err := remote.writeContentStore(data)
	if err != nil {
		return err
	}

	architecture := runtime.GOARCH
	os := runtime.GOOS
	if remote.targetConfigDesc.Platform != nil {
		architecture = remote.targetConfigDesc.Platform.Architecture
		os = remote.targetConfigDesc.Platform.OS
	}

	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    *digest,
		Size:      int64(size),
		Platform: &ocispec.Platform{
			Architecture: architecture,
			OS:           os,
			OSFeatures:   []string{ManifestOSFeatureNydus},
		},
	}

	if err := remote.client.Push(remote.ctx, remote.target, manifestDesc, containerd.WithResolver(remote.pushResolver)); err != nil {
		return errors.Wrap(err, "push image manifest")
	}

	remote.targetManifestDesc = &manifestDesc

	return nil
}

// PushManifestIndex push manifest list to target registry
func (remote *Remote) PushManifestIndex() error {
	logrus.Infof("Pushing manifest index")

	if remote.sourceManifestDesc.Platform == nil {
		remote.sourceManifestDesc.Platform = &ocispec.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		}
	}

	manifestIndex := ManifestIndex{
		MediaType: ocispec.MediaTypeImageIndex,
		Index: ocispec.Index{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Manifests: []ocispec.Descriptor{
				*remote.sourceManifestDesc,
				*remote.targetManifestDesc,
			},
		},
	}

	data, err := json.Marshal(manifestIndex)
	if err != nil {
		return err
	}

	size, digest, err := remote.writeContentStore(data)
	if err != nil {
		return err
	}

	manifestIndexDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageIndex,
		Digest:    *digest,
		Size:      int64(size),
	}

	if err := remote.client.Push(remote.ctx, remote.target, manifestIndexDesc, containerd.WithResolver(remote.pushResolver)); err != nil {
		return errors.Wrap(err, "push image manifest index")
	}

	return nil
}
