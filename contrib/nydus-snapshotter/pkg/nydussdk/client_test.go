/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydussdk

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/nydussdk/model"
)

func prepareNydusServer(t *testing.T) (string, func()) {
	mockSocket := "testdata/nydus.sock"
	_, err := os.Stat(mockSocket)
	if err == nil {
		_ = os.Remove(mockSocket)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		info := model.DaemonInfo{
			ID:      "testid",
			Version: "1.0",
			State:   "Running",
		}
		w.Header().Set("Content-Type", "application/json")
		j, _ := json.Marshal(info)
		w.Write(j)
	}))
	unixListener, err := net.Listen("unix", mockSocket)
	require.Nil(t, err)
	ts.Listener = unixListener
	ts.Start()
	return mockSocket, func() {
		ts.Close()
	}
}

func TestNydusClient_CheckStatus(t *testing.T) {
	sock, dispose := prepareNydusServer(t)
	defer dispose()
	client, err := NewNydusClient(sock)
	require.Nil(t, err)
	info ,err := client.CheckStatus()
	require.Nil(t, err)
	assert.Equal(t, "Running", info.State)
	assert.Equal(t, "testid", info.ID)
}
