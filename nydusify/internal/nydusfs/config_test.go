/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"strings"
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
				Addr:       "https://reg.example.com",
				Repository: "library/ubuntu",
				Auth:       got,
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

func TestRegistryBackendConfigDragonfly(t *testing.T) {
	render := func(df *dragonflySection) string {
		out, err := yaml.Marshal(storageConfig{Backend: backendSection{
			Type:   "registry",
			Config: registryBackendConfig{Addr: "https://reg.example.com", Dragonfly: df},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	if out := render(nil); strings.Contains(out, "dragonfly") {
		t.Fatalf("dragonfly section rendered while disabled:\n%s", out)
	}
	out := render(&dragonflySection{SchedulerEndpoint: "http://127.0.0.1:8002"})
	if !strings.Contains(out, "dragonfly:\n") || !strings.Contains(out, "scheduler_endpoint: http://127.0.0.1:8002") {
		t.Fatalf("dragonfly section missing:\n%s", out)
	}
}
