package build

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

type checkReport struct {
	Kind  string `json:"kind"`
	Blobs []struct {
		SlotSHA256 string `json:"slot_sha256"`
		Verified   bool   `json:"verified"`
	} `json:"blobs"`
}

func nydusCheck(t testing.TB, args ...string) (checkReport, error) {
	t.Helper()
	args = append([]string{"check", "--output", "json"}, args...)
	cmd := env.Command(t, env.Nydus(t), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	requireCleanExit(t, err)

	if err != nil {
		err = fmt.Errorf("nydus %s: %w\n%s%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}

	var report checkReport

	if out := bytes.TrimSpace(stdout.Bytes()); len(out) > 0 && out[0] == '{' {
		assert.NoError(t, json.Unmarshal(out, &report))
	}

	return report, err
}

func requireVerified(t testing.TB, bootstrap, blobDir string, blobs []string) {
	t.Helper()
	report, err := nydusCheck(t, "--bootstrap", bootstrap, "--blob-dir", blobDir)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "bootstrap", report.Kind) {
		t.FailNow()
	}
	if !assert.Len(t, report.Blobs, len(blobs)) {
		t.FailNow()
	}

	for i, blob := range report.Blobs {
		if !assert.Equal(t, filepath.Base(blobs[i]), blob.SlotSHA256) {
			t.FailNow()
		}

		assert.True(t, blob.Verified)
	}
}
