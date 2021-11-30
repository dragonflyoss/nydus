/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package registry

import (
	"reflect"
	"testing"
)

func TestConvertToVPCHost1(t *testing.T) {
	type args struct {
		registryHost string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "with no vpc registry",
			args: args{
				registryHost: "acr-nydus-registry.cn-hangzhou.cr.aliyuncs.com",
			},
			want: "acr-nydus-registry-vpc.cn-hangzhou.cr.aliyuncs.com",
		},
		{
			name: "with vpc registry",
			args: args{
				registryHost: "acr-nydus-registry-vpc.cn-hangzhou.cr.aliyuncs.com",
			},
			want: "acr-nydus-registry-vpc.cn-hangzhou.cr.aliyuncs.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertToVPCHost(tt.args.registryHost); got != tt.want {
				t.Errorf("ConvertToVPCHost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseImage(t *testing.T) {
	type args struct {
		imageID string
	}
	tests := []struct {
		name    string
		args    args
		want    Image
		wantErr bool
	}{
		{
			name: "multi path",
			args: args{
				imageID: "localhost:5000/hello-world/foo/bar:latest",
			},
			want: Image{
				Host: "localhost:5000",
				Repo: "hello-world/foo/bar",
			},
			wantErr: false,
		},
		{
			name: "no namespace",
			args: args{
				imageID: "localhost:5000/bar:latest",
			},
			want: Image{
				Host: "localhost:5000",
				Repo: "bar",
			},
			wantErr: false,
		},
		{
			name: "normal",
			args: args{
				imageID: "nydus-registry.cn-hangzhou.cr.aliyuncs.com/poc/tomcat:latest-app-nydus-platform",
			},
			want: Image{
				Host: "nydus-registry.cn-hangzhou.cr.aliyuncs.com",
				Repo: "poc/tomcat",
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				imageID: "nydus-registry.cn-hangzhou.cr.aliyuncs.com/:latest-app-nydus-platform",
			},
			want: Image{
				Host: "",
				Repo: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseImage(tt.args.imageID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseImage() got = %v, want %v", got, tt.want)
			}
		})
	}
}
