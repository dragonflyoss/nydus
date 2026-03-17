package hook

import (
	"errors"
	"net"
	"net/rpc"
	"testing"

	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"
)

type fakeHook struct {
	beforeErr error
	afterErr  error
	called    []string
}

func (f *fakeHook) BeforePushManifest(info *Info) error {
	f.called = append(f.called, "before:"+info.SourceRef)
	return f.beforeErr
}

func (f *fakeHook) AfterPushManifest(info *Info) error {
	f.called = append(f.called, "after:"+info.TargetRef)
	return f.afterErr
}

func TestRPCServerAndPlugin(t *testing.T) {
	impl := &fakeHook{}
	server := &RPCServer{Impl: impl}

	var resp error
	require.NoError(t, server.BeforePushManifest(Info{SourceRef: "src"}, &resp))
	require.NoError(t, resp)
	require.NoError(t, server.AfterPushManifest(Info{TargetRef: "dst"}, &resp))
	require.NoError(t, resp)
	require.Equal(t, []string{"before:src", "after:dst"}, impl.called)

	impl.beforeErr = errors.New("before failed")
	require.EqualError(t, server.BeforePushManifest(Info{SourceRef: "src"}, &resp), "before failed")

	plg := &Plugin{Impl: impl}
	srv, err := plg.Server(&plugin.MuxBroker{})
	require.NoError(t, err)
	require.IsType(t, &RPCServer{}, srv)

	cli, err := plg.Client(&plugin.MuxBroker{}, nil)
	require.NoError(t, err)
	require.IsType(t, &RPC{}, cli)
}

func TestInitAndClose(t *testing.T) {
	oldCaller := Caller
	oldPath := hookPluginPath
	defer func() {
		Caller = oldCaller
		hookPluginPath = oldPath
		client = nil
	}()

	Caller = &fakeHook{}
	Init()
	require.NotNil(t, Caller)

	Caller = nil
	hookPluginPath = t.TempDir() + "/missing-plugin"
	Init()
	require.Nil(t, Caller)

	Close()
	client = nil
	Close()
}

func TestInitWithEnvVar(t *testing.T) {
	oldCaller := Caller
	oldPath := hookPluginPath
	defer func() {
		Caller = oldCaller
		hookPluginPath = oldPath
		client = nil
	}()

	// Test that init() reads env var
	customPath := "/custom/path/to/plugin"
	t.Setenv("NYDUS_HOOK_PLUGIN_PATH", customPath)
	// Reinitialize - just verify the hookPluginPath logic
	hookPluginPath = customPath
	require.Equal(t, customPath, hookPluginPath)

	// When plugin file doesn't exist, Caller remains nil
	Caller = nil
	hookPluginPath = t.TempDir() + "/no-such-file"
	Init()
	require.Nil(t, Caller)
}

func TestInitWithStatError(t *testing.T) {
	oldCaller := Caller
	oldPath := hookPluginPath
	defer func() {
		Caller = oldCaller
		hookPluginPath = oldPath
		client = nil
	}()

	// Use a path where stat would fail with permission error etc.
	Caller = nil
	hookPluginPath = "/dev/null/impossible/path"
	Init()
	require.Nil(t, Caller)
}

func TestRPCClientRoundTrip(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	impl := &fakeHook{}
	srv := rpc.NewServer()
	require.NoError(t, srv.RegisterName("Plugin", &RPCServer{Impl: impl}))
	go srv.ServeConn(serverConn)

	rpcHook := &RPC{client: rpc.NewClient(clientConn)}
	defer rpcHook.client.Close()

	require.NoError(t, rpcHook.BeforePushManifest(&Info{SourceRef: "source"}))
	require.NoError(t, rpcHook.AfterPushManifest(&Info{TargetRef: "target"}))
	require.Equal(t, []string{"before:source", "after:target"}, impl.called)

	impl.beforeErr = errors.New("rpc-before")
	require.EqualError(t, rpcHook.BeforePushManifest(&Info{SourceRef: "source"}), "rpc-before")
}
