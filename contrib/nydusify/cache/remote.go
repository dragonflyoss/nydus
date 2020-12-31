// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	dockerref "github.com/containerd/containerd/reference/docker"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func newDefaultClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
			TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}
}

func hostWithCredential(host string) (string, string, error) {
	if host == "registry-1.docker.io" {
		host = "https://index.docker.io/v1/"
	}

	config := dockerconfig.LoadDefaultConfigFile(os.Stderr)
	authConfig, err := config.GetAuthConfig(host)
	if err != nil {
		return "", "", err
	}

	return authConfig.Username, authConfig.Password, nil
}

type RemoteOpt struct {
	Ref      string
	Insecure bool
}

type Remote struct {
	parsed   reference.Named
	resolver remotes.Resolver
}

func NewRemote(opt RemoteOpt) (*Remote, error) {
	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(docker.NewAuthorizer(
			newDefaultClient(),
			hostWithCredential,
		)),
		docker.WithClient(newDefaultClient()),
		docker.WithPlainHTTP(func(host string) (bool, error) {
			insecure, err := docker.MatchLocalhost(host)
			if err != nil {
				return false, err
			}
			if insecure {
				return true, nil
			}
			return opt.Insecure, nil
		}),
	)

	reference, err := dockerref.ParseAnyReference(opt.Ref)
	if err != nil {
		return nil, err
	}
	parsed := reference.(dockerref.Named)

	resolver := docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})

	return &Remote{
		parsed:   parsed,
		resolver: resolver,
	}, nil
}

func (remote *Remote) Push(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (content.Writer, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	pusher, err := remote.resolver.Pusher(ctx, ref)
	if err != nil {
		return nil, err
	}

	writer, err := pusher.Push(ctx, desc)
	if err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, err
	}

	return writer, nil
}

func (remote *Remote) PushByReader(ctx context.Context, desc *ocispec.Descriptor, byDigest bool, reader io.Reader) error {
	writer, err := remote.Push(ctx, *desc, byDigest)
	if err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	defer writer.Close()

	return content.Copy(ctx, writer, reader, desc.Size, desc.Digest)
}

func (remote *Remote) Pull(ctx context.Context, desc ocispec.Descriptor, byDigest bool) (io.ReadCloser, error) {
	var ref string
	if byDigest {
		ref = remote.parsed.Name()
	} else {
		ref = reference.TagNameOnly(remote.parsed).String()
	}

	puller, err := remote.resolver.Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}

	reader, err := puller.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}

	return reader, nil
}

func (remote *Remote) Resolve(ctx context.Context) (*ocispec.Descriptor, error) {
	ref := reference.TagNameOnly(remote.parsed).String()

	_, desc, err := remote.resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	return &desc, nil
}
