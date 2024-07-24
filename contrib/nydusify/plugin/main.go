package main

import (
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/hook"
)

type LocalHook struct {
}

func (h *LocalHook) BeforePushManifest(_ *hook.Info) error {
	return nil
}

func (h *LocalHook) AfterPushManifest(_ *hook.Info) error {
	return nil
}

func main() {
	hook.NewPlugin(&LocalHook{})
}
