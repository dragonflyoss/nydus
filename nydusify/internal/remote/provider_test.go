/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import "testing"

func TestSameRepository(t *testing.T) {
	tests := []struct {
		name      string
		left      string
		right     string
		want      bool
		wantError bool
	}{
		{
			name:  "same explicit repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/image:child",
			want:  true,
		},
		{
			name:  "different repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/other:child",
			want:  false,
		},
		{
			name:  "docker hub shorthand",
			left:  "busybox:1.36",
			right: "docker.io/library/busybox:latest",
			want:  true,
		},
		{
			name:  "digest reference",
			left:  "localhost:5000/repo/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			right: "localhost:5000/repo/image:tag",
			want:  true,
		},
		{
			name:      "invalid reference",
			left:      "not a valid reference",
			right:     "localhost:5000/repo/image:tag",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SameRepository(tt.left, tt.right)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SameRepository returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("SameRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}
