/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestCommandFailures(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))
	missing := filepath.Join(dir, "missing")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"annotation", []string{"convert", "--source", dir, "--manifest-annotation", "bad"}, "expected key=value"},
		{"inputs", []string{"convert"}, "source"},
		{"compressor", []string{"convert", "--source", dir, "--compressor", "invalid"}, "unsupported --compressor"},
		{"oci-annotation", []string{"convert", "--source", dir, "--compressor", "oci-tar", "--manifest-annotation", "key=value"}, "only supported"},
		{"chunk-overflow", []string{"convert", "--source", dir, "--chunk-size", "4294967296"}, "fit uint32"},
		{"convert-platform", []string{"convert", "--source", dir, "--platform", "a/b/c/d"}, "invalid platform"},
		{"convert-work", []string{"convert", "--source", dir, "--work-dir", blocked}, "create work dir"},
		{"oci-artifact", []string{"convert", "--bootstrap", blocked, "--blob", blocked, "--compressor", "oci-tar"}, "artifacts back to OCI"},
		{"oci-directory", []string{"convert", "--source", dir, "--compressor", "oci-tar"}, "exactly one nydus image"},
		{"oci-pull", []string{"convert", "--source", "://bad", "--compressor", "oci-tar"}, "pull"},
		{"parent-reference", []string{"convert", "--bootstrap", blocked, "--parent-image", "://bad"}, "reference"},
		{"parent-repository", []string{"convert", "--bootstrap", blocked, "--parent-image", "example.test/other:tag"}, "same repository"},
		{"artifact-inspect", []string{"convert", "--bootstrap", blocked, "--blob", blocked, "--builder", missing}, "inspect bootstrap"},
		{"directory-build", []string{"convert", "--source", dir, "--builder", missing}, "convert"},
		{"image-pull", []string{"convert", "--source", "://bad"}, "pull"},
		{"check-platform", []string{"check", "--platform", "a/b/c/d"}, "invalid platform"},
		{"check-work", []string{"check", "--work-dir", blocked}, "create work dir"},
		{"mount-platform", []string{"mount", "--platform", "a/b/c/d"}, "invalid platform"},
		{"mount-point", []string{"mount", "--mountpoint", blocked}, "create mountpoint"},
		{"mount-work", []string{"mount", "--work-dir", blocked}, "create work dir"},
		{"optimize-platform", []string{"optimize", "--platform", "a/b/c/d"}, "invalid platform"},
		{"optimize-work", []string{"optimize", "--work-dir", blocked}, "create work dir"},
		{"optimize-reference", []string{"optimize", "--source", "://bad"}, "reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"nydusify", tc.args[0], "--target", "example.test/image:tag", "--work-dir", t.TempDir()}
			if tc.args[0] == "mount" {
				args = append(args, "--mountpoint", t.TempDir())
			}
			if tc.args[0] == "optimize" {
				args = append(args, "--source", "example.test/image:source", "--trace-file", blocked)
			}
			args = append(args, tc.args[1:]...)
			app := &cli.App{Writer: io.Discard, ErrWriter: io.Discard,
				Commands: []*cli.Command{convertCommand(), checkCommand(), mountCommand(), optimizeCommand()}}
			require.ErrorContains(t, app.Run(args), tc.want)
		})
	}
}

func TestParseManifestAnnotations(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:   "multiple annotations",
			values: []string{"backend=dragonfly-snapshotter", "digest=xxh3:0123456789abcdef", "empty="},
			want:   map[string]string{"backend": "dragonfly-snapshotter", "digest": "xxh3:0123456789abcdef", "empty": ""},
		},
		{
			name:   "value contains equals",
			values: []string{"key=value=tail"},
			want:   map[string]string{"key": "value=tail"},
		},
		{
			name:   "duplicate key uses last value",
			values: []string{"key=old", "key=new"},
			want:   map[string]string{"key": "new"},
		},
		{name: "missing equals", values: []string{"key"}, wantErr: true},
		{name: "empty key", values: []string{"=value"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseManifestAnnotations(tt.values)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseManifestAnnotations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseManifestAnnotations() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManifestAnnotationFlagPreservesCommas(t *testing.T) {
	var values []string
	annotationFlag := &manifestAnnotationValue{}
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.GenericFlag{Name: "manifest-annotation", Value: annotationFlag},
		},
		Action: func(c *cli.Context) error {
			values = manifestAnnotationValues(c)
			return nil
		},
	}

	const annotation = `io.cri-proxy.snapshot.vm-rootfs={"path":"rootfs.img","digest":"xxh3:0123456789abcdef"}`
	if err := app.Run([]string{
		"nydusify",
		"--manifest-annotation", annotation,
	}); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(values, []string{annotation}) {
		t.Fatalf("manifest annotation values = %q, want %q", values, []string{annotation})
	}
}

func TestManifestAnnotationFlagDoesNotChangeSliceFlags(t *testing.T) {
	annotationFlag := &manifestAnnotationValue{}
	var sources []string
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "source"},
			&cli.GenericFlag{Name: "manifest-annotation", Value: annotationFlag},
		},
		Action: func(c *cli.Context) error {
			sources = c.StringSlice("source")
			return nil
		},
	}

	if err := app.Run([]string{"nydusify", "--source", "lower,upper"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sources, []string{"lower", "upper"}) {
		t.Fatalf("source values = %q, want %q", sources, []string{"lower", "upper"})
	}
}
