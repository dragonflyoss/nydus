/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBasicAuthConfigEncodesRegistryBackendAuthString(t *testing.T) {
	got := basicAuthConfig("user", "pass")
	if got != "dXNlcjpwYXNz" {
		t.Fatalf("unexpected basic auth config: %q", got)
	}

	cfg := storageConfig{
		Backend: backendSection{
			Type: "registry",
			Config: registryBackendConfig{
				Host: "reg.example.com",
				Repo: "library/ubuntu",
				Auth: got,
			},
		},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := yaml.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	backend := decoded["backend"].(map[string]any)
	config := backend["config"].(map[string]any)
	if _, ok := config["auth"].(string); !ok {
		t.Fatalf("auth should be rendered as string, got %#v", config["auth"])
	}
}
