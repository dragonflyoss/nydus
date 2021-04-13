/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import "testing"

func Test_digest_Sha256(t *testing.T) {
	tests := []struct {
		name string
		d    digest
		want string
	}{
		{
			name: "testdigest",
			d:    digest("sha256:12345"),
			want: "12345",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.Sha256(); got != tt.want {
				t.Errorf("Sha256() = %v, want %v", got, tt.want)
			}
		})
	}
}
