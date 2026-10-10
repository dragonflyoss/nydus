/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"reflect"
	"testing"

	"github.com/urfave/cli/v2"
)

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
