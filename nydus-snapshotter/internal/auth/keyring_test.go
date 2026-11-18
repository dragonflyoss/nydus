/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	mockAuthConfig = authConfig{Username: "user", Password: "pass"}

	mockBasic = base64.StdEncoding.EncodeToString([]byte("user:pass"))
)

func TestKeyring_lookup(t *testing.T) {
	tests := []struct {
		name   string
		auths  map[string]authConfig
		target registryKey
		expect func(t *testing.T, creds []credential)
	}{
		{
			name:   "match host",
			auths:  map[string]authConfig{"registry.example.com": mockAuthConfig},
			target: "registry.example.com/team/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 1)
				assert.Equal(registryKey("registry.example.com"), creds[0].key)
				assert.Equal("test", creds[0].source)
			},
		},
		{
			name:   "strip scheme and v2 path",
			auths:  map[string]authConfig{"https://registry.example.com/v2/": mockAuthConfig},
			target: "registry.example.com/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 1)
				assert.Equal(registryKey("registry.example.com"), creds[0].key)
			},
		},
		{
			name:   "match wildcard host",
			auths:  map[string]authConfig{"*.example.com": mockAuthConfig},
			target: "registry.example.com/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 1)
			},
		},
		{
			name:   "wildcard needs the same number of host parts",
			auths:  map[string]authConfig{"*.example.com": mockAuthConfig},
			target: "example.com/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Empty(creds)
			},
		},
		{
			name:   "port must match",
			auths:  map[string]authConfig{"registry.example.com:5000": mockAuthConfig},
			target: "registry.example.com/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Empty(creds)
			},
		},
		{
			name:   "match path prefix",
			auths:  map[string]authConfig{"registry.example.com/team": mockAuthConfig},
			target: "registry.example.com/team/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 1)
			},
		},
		{
			name:   "path prefix mismatch",
			auths:  map[string]authConfig{"registry.example.com/team": mockAuthConfig},
			target: "registry.example.com/other/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Empty(creds)
			},
		},
		{
			name: "most specific key first",
			auths: map[string]authConfig{
				"registry.example.com":      {Username: "host"},
				"registry.example.com/team": {Username: "team"},
				"*.example.com":             {Username: "wildcard"},
			},
			target: "registry.example.com/team/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 3)
				assert.Equal("team", creds[0].Username)
				assert.Equal("host", creds[1].Username)
				assert.Equal("wildcard", creds[2].Username)
			},
		},
		{
			name: "docker hub aliases match docker.io",
			auths: map[string]authConfig{
				"https://index.docker.io/v1/": {Username: "index"},
				"registry-1.docker.io":        {Username: "registry-1"},
				"docker.io":                   {Username: "docker"},
			},
			target: "docker.io/library/ubuntu",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 3)
				assert.Equal(registryKey("docker.io"), creds[0].key)
				assert.Equal("docker", creds[0].Username)
				assert.Equal("index", creds[1].Username)
				assert.Equal("registry-1", creds[2].Username)
			},
		},
		{
			name: "skip invalid registry",
			auths: map[string]authConfig{
				"registry.example.com/%zz": mockAuthConfig,
				"registry.example.com":     mockAuthConfig,
			},
			target: "registry.example.com/app",
			expect: func(t *testing.T, creds []credential) {
				assert := assert.New(t)
				assert.Len(creds, 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := &keyring{}
			k.add("test", tc.auths)
			tc.expect(t, k.lookup(tc.target))
		})
	}
}

func TestRegistryKey_matches(t *testing.T) {
	tests := []struct {
		name   string
		key    registryKey
		target registryKey
		expect func(t *testing.T, matched bool, err error)
	}{
		{
			name:   "host and path prefix",
			key:    "registry.example.com/team",
			target: "registry.example.com/team/app",
			expect: func(t *testing.T, matched bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(matched)
			},
		},
		{
			name:   "another port",
			key:    "registry.example.com:5000",
			target: "registry.example.com:5001/app",
			expect: func(t *testing.T, matched bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(matched)
			},
		},
		{
			name:   "key that is no url",
			key:    "%zz",
			target: "registry.example.com/app",
			expect: func(t *testing.T, matched bool, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.False(matched)
			},
		},
		{
			name:   "target that is no url",
			key:    "registry.example.com",
			target: "%zz",
			expect: func(t *testing.T, matched bool, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.False(matched)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := tc.key.matches(tc.target)
			tc.expect(t, matched, err)
		})
	}
}

func TestCredential_basic(t *testing.T) {
	tests := []struct {
		name   string
		auth   authConfig
		expect func(t *testing.T, basic string)
	}{
		{
			name: "username and password",
			auth: mockAuthConfig,
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Equal(mockBasic, basic)
			},
		},
		{
			name: "padded auth",
			auth: authConfig{Auth: base64.StdEncoding.EncodeToString([]byte("user:pass1"))},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Equal(base64.StdEncoding.EncodeToString([]byte("user:pass1")), basic)
			},
		},
		{
			name: "unpadded auth",
			auth: authConfig{Auth: base64.RawStdEncoding.EncodeToString([]byte("user:pass1"))},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Equal(base64.StdEncoding.EncodeToString([]byte("user:pass1")), basic)
			},
		},
		{
			name: "auth wins over username and password",
			auth: authConfig{Username: "other", Password: "other", Auth: mockBasic},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Equal(mockBasic, basic)
			},
		},
		{
			name: "skip identity token",
			auth: authConfig{Auth: mockBasic, IdentityToken: "token"},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Empty(basic)
			},
		},
		{
			name: "skip registry token",
			auth: authConfig{RegistryToken: "token"},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Empty(basic)
			},
		},
		{
			name: "skip malformed auth",
			auth: authConfig{Auth: "!!!"},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Empty(basic)
			},
		},
		{
			name: "skip auth without colon",
			auth: authConfig{Auth: base64.StdEncoding.EncodeToString([]byte("user"))},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Empty(basic)
			},
		},
		{
			name: "skip missing username",
			auth: authConfig{Password: "pass"},
			expect: func(t *testing.T, basic string) {
				assert := assert.New(t)
				assert.Empty(basic)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := &credential{authConfig: tc.auth}
			tc.expect(t, cred.basic())
		})
	}
}
