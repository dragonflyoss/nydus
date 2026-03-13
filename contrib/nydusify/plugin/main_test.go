package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/hook"
)

var _ hook.Hook = (*LocalHook)(nil)

func TestLocalHook(t *testing.T) {
	localHook := &LocalHook{}
	require.NoError(t, localHook.BeforePushManifest(&hook.Info{}))
	require.NoError(t, localHook.AfterPushManifest(&hook.Info{}))
}
