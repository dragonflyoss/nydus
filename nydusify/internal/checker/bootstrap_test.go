/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestBootstrapRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		builder string
		images  func(img *nydusfs.Image) (*nydusfs.Image, *nydusfs.Image)
		expect  func(t *testing.T, dir, workDir string, err error)
	}{
		{
			name:    "skip oci and absent images",
			builder: "exit 0\n",
			images: func(_ *nydusfs.Image) (*nydusfs.Image, *nydusfs.Image) {
				return &nydusfs.Image{Kind: nydusfs.KindOCI}, nil
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Nil(mockBuilderArgs(t, dir))
			},
		},
		{
			name:    "check source and target bootstraps",
			builder: "exit 0\n",
			images: func(img *nydusfs.Image) (*nydusfs.Image, *nydusfs.Image) {
				return img, img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				args := mockBuilderArgs(t, dir)
				if !assert.Len(args, 6) {
					t.FailNow()
				}

				assert.Equal([]string{"check", "--bootstrap"}, args[:2])
				assert.True(strings.HasPrefix(args[2], filepath.Join(workDir, "bootstrap-source-")))
				assert.Equal([]string{"check", "--bootstrap"}, args[3:5])
				assert.True(strings.HasPrefix(args[5], filepath.Join(workDir, "bootstrap-target-")))
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "report nydus check output",
			builder: "echo 'invalid superblock' >&2\nexit 1\n",
			images: func(img *nydusfs.Image) (*nydusfs.Image, *nydusfs.Image) {
				return img, nil
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "source bootstrap: nydus check failed: invalid superblock")
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name: "report missing builder",
			images: func(img *nydusfs.Image) (*nydusfs.Image, *nydusfs.Image) {
				return nil, img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "target bootstrap: nydus check failed")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fs, img := mountRule(t, "")
			source, target := tc.images(img)
			rule := bootstrapRule{cs: fs.cs, builder: mockBuilder(t, dir, tc.builder), workDir: fs.workDir, source: source, target: target}
			tc.expect(t, dir, fs.workDir, rule.Validate(context.Background()))
		})
	}
}

func TestRunNydusCheck(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder bootstrap checks")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source := t.TempDir()
	if !assert.NoError(t, os.WriteFile(filepath.Join(source, "hostname"), []byte("nydus\n"), 0o644)) {
		t.FailNow()
	}

	var blob bytes.Buffer
	if !assert.NoError(t, nydus.BuildBlob(ctx, &blob, source, nydus.PackOption{BuilderPath: builder, WorkDir: t.TempDir()})) {
		t.FailNow()
	}

	bootstrap, _, err := nydus.MergeBootstrap(ctx, []nydus.Layer{{Digest: digest.FromBytes(blob.Bytes()), ReaderAt: bytes.NewReader(blob.Bytes())}},
		nydus.MergeOption{BuilderPath: builder, WorkDir: t.TempDir()})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	tests := []struct {
		name      string
		bootstrap []byte
		expect    func(t *testing.T, err error)
	}{
		{
			name:      "accept merged bootstrap",
			bootstrap: bootstrap,
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:      "reject truncated bootstrap",
			bootstrap: bootstrap[:len(bootstrap)/2],
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus check failed")
			},
		},
		{
			name:      "reject arbitrary bytes",
			bootstrap: []byte("bootstrap"),
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus check failed")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image.boot")
			if !assert.NoError(t, os.WriteFile(path, tc.bootstrap, 0o600)) {
				t.FailNow()
			}

			tc.expect(t, runNydusCheck(ctx, builder, path))
		})
	}
}
