/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import "testing"

func TestValidateConvertInputs(t *testing.T) {
	tests := []struct {
		name         string
		input        ConvertInput
		wantArtifact bool
		wantError    bool
	}{
		{
			name:  "normal source mode",
			input: ConvertInput{Sources: []string{"localhost:5000/repo/image:tag"}},
		},
		{
			name:         "artifact with local blob",
			input:        ConvertInput{BootstrapPath: "/tmp/image.boot", BlobPaths: []string{"/tmp/blob"}},
			wantArtifact: true,
		},
		{
			name:         "artifact with parent image only",
			input:        ConvertInput{BootstrapPath: "/tmp/image.boot", ParentImages: []string{"localhost:5000/repo/image:parent"}},
			wantArtifact: true,
		},
		{
			name:      "missing all inputs",
			wantError: true,
		},
		{
			name: "source mixed with artifact input",
			input: ConvertInput{
				Sources:       []string{"localhost:5000/repo/image:tag"},
				BootstrapPath: "/tmp/image.boot",
				BlobPaths:     []string{"/tmp/blob"},
			},
			wantError: true,
		},
		{
			name:      "artifact missing bootstrap",
			input:     ConvertInput{BlobPaths: []string{"/tmp/blob"}},
			wantError: true,
		},
		{
			name:      "bootstrap without artifact payload",
			input:     ConvertInput{BootstrapPath: "/tmp/image.boot"},
			wantError: true,
		},
		{
			name: "multiple parent images",
			input: ConvertInput{
				BootstrapPath: "/tmp/image.boot",
				ParentImages: []string{
					"localhost:5000/repo/image:parent-a",
					"localhost:5000/repo/image:parent-b",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArtifact, err := ValidateConvertInputs(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateConvertInputs returned error: %v", err)
			}
			if gotArtifact != tt.wantArtifact {
				t.Fatalf("artifactMode = %v, want %v", gotArtifact, tt.wantArtifact)
			}
		})
	}
}
