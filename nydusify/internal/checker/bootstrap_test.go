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
	"regexp"
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
		setup   func(rule *bootstrapRule, img *nydusfs.Image)
		expect  func(t *testing.T, dir, workDir string, err error)
	}{
		{
			name:    "skip oci and absent images",
			builder: "exit 0\n",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				rule.source = &nydusfs.Image{Kind: nydusfs.KindOCI}
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
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				rule.source, rule.target = img, img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Regexp("^check --bootstrap "+regexp.QuoteMeta(filepath.Join(workDir, "bootstrap-source-"))+`\S+ check --bootstrap `+regexp.QuoteMeta(filepath.Join(workDir, "bootstrap-target-"))+`\S+$`, strings.Join(mockBuilderArgs(t, dir), " "))
				entries, err := os.ReadDir(workDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "report nydus check output",
			builder: "echo 'invalid superblock' >&2\nexit 1\n",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				rule.source = img
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
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				rule.target = img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "target bootstrap: nydus check failed")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "reject source without bootstrap",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				img.Bootstrap = nil
				rule.source = img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source bootstrap: nydus image is missing its bootstrap layer")
			},
		},
		{
			name: "reject target without bootstrap",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				img.Bootstrap = nil
				rule.target = img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "target bootstrap: nydus image is missing its bootstrap layer")
			},
		},
		{
			name: "report missing work dir",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				rule.workDir = filepath.Join(rule.workDir, "missing")
				rule.source = img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "source bootstrap: create scratch dir")
			},
		},
		{
			name: "report missing bootstrap blob",
			setup: func(rule *bootstrapRule, img *nydusfs.Image) {
				img.Bootstrap.Digest = digest.FromString("absent bootstrap")
				rule.source = img
			},
			expect: func(t *testing.T, dir, workDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "source bootstrap: extract bootstrap")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fs, img := mockFilesystemRule(t, "")
			rule := &bootstrapRule{cs: fs.cs, builder: mockBuilder(t, dir, tc.builder), workDir: fs.workDir}
			tc.setup(rule, img)

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
	if err := os.WriteFile(filepath.Join(source, "hostname"), []byte("nydus\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var blob bytes.Buffer
	if err := nydus.BuildBlob(ctx, &blob, source, nydus.PackOption{BuilderPath: builder, WorkDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}

	bootstrap, _, err := nydus.MergeBootstrap(ctx, []nydus.Layer{{Digest: digest.FromBytes(blob.Bytes()), ReaderAt: bytes.NewReader(blob.Bytes())}},
		nydus.MergeOption{BuilderPath: builder, WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
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
			if err := os.WriteFile(path, tc.bootstrap, 0o600); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, runNydusCheck(ctx, builder, path))
		})
	}
}
