// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"net/rpc"
	"os"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var hookPluginPath = "./nydus-hook-plugin"

func init() {
	envPath := os.Getenv("NYDUS_HOOK_PLUGIN_PATH")
	if envPath != "" {
		hookPluginPath = envPath
	}
}

type Blob struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

type Info struct {
	BootstrapPath string `json:"bootstrap_path"`
	SourceRef     string `json:"source_ref"`
	TargetRef     string `json:"target_ref"`
	Blobs         []Blob `json:"blobs"`
}

type Hook interface {
	BeforePushManifest(info *Info) error
	AfterPushManifest(info *Info) error
}

type RPC struct{ client *rpc.Client }

func (h *RPC) BeforePushManifest(info *Info) error {
	var resp error
	err := h.client.Call("Plugin.BeforePushManifest", info, &resp)
	if err != nil {
		return err
	}
	return resp
}

func (h *RPC) AfterPushManifest(info *Info) error {
	var resp error
	err := h.client.Call("Plugin.AfterPushManifest", info, &resp)
	if err != nil {
		return err
	}
	return resp
}

type RPCServer struct {
	Impl Hook
}

func (s *RPCServer) BeforePushManifest(info Info, resp *error) error {
	*resp = s.Impl.BeforePushManifest(&info)
	return *resp
}

func (s *RPCServer) AfterPushManifest(info Info, resp *error) error {
	*resp = s.Impl.AfterPushManifest(&info)
	return *resp
}

type Plugin struct {
	Impl Hook
}

func (p *Plugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &RPCServer{Impl: p.Impl}, nil
}

func (Plugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &RPC{client: c}, nil
}

var Caller Hook

var handshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NYDUS_HOOK_PLUGIN",
	MagicCookieValue: "nydus-hook-plugin",
}

func NewPlugin(pluginImpl Hook) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"hook": &Plugin{Impl: pluginImpl},
		},
	})
}

var client *plugin.Client

func Init() {
	if Caller != nil {
		return
	}

	if _, err := os.Stat(hookPluginPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		logrus.Errorln(errors.Wrapf(err, "try load hook plugin %s", hookPluginPath))
		return
	}

	var pluginMap = map[string]plugin.Plugin{
		"hook": &Plugin{},
	}

	client = plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
		Cmd:             exec.Command(hookPluginPath),
		Logger: hclog.New(&hclog.LoggerOptions{
			Output: hclog.DefaultOutput,
			Level:  hclog.Error,
			Name:   "plugin",
		}),
	})

	rpcClient, err := client.Client()
	if err != nil {
		logrus.WithError(err).Error("Failed to create rpc client")
		return
	}

	raw, err := rpcClient.Dispense("hook")
	if err != nil {
		logrus.WithError(err).Error("Failed to dispense hook")
		return
	}

	logrus.Infof("[HOOK] Loaded hook plugin %s", hookPluginPath)

	Caller = raw.(Hook)
}

func Close() {
	if client != nil {
		defer client.Kill()
	}
}
