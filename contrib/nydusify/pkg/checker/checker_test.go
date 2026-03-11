package checker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/rule"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
)

func TestNew(t *testing.T) {
	t.Run("target remote failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(provider.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return nil, errors.New("target remote failed")
		})
		defer patches.Reset()

		checker, err := New(Opt{Target: "target", ExpectedArch: "amd64"})
		require.Nil(t, checker)
		require.ErrorContains(t, err, "init target image parser")
	})

	t.Run("target parser failed", func(t *testing.T) {
		remotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return &remote.Remote{}, nil
		})
		defer remotePatches.Reset()

		parserPatches := gomonkey.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
			return nil, errors.New("parser failed")
		})
		defer parserPatches.Reset()

		checker, err := New(Opt{Target: "target", ExpectedArch: "amd64"})
		require.Nil(t, checker)
		require.ErrorContains(t, err, "failed to create parser")
	})

	t.Run("source remote failed", func(t *testing.T) {
		calls := 0
		remotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(ref string, insecure bool) (*remote.Remote, error) {
			calls++
			if calls == 1 {
				return &remote.Remote{Ref: ref}, nil
			}
			return nil, errors.New("source remote failed")
		})
		defer remotePatches.Reset()

		parserPatches := gomonkey.ApplyFunc(parser.New, func(remoter *remote.Remote, arch string) (*parser.Parser, error) {
			return &parser.Parser{Remote: remoter}, nil
		})
		defer parserPatches.Reset()

		checker, err := New(Opt{Target: "target", Source: "source", ExpectedArch: "amd64"})
		require.Nil(t, checker)
		require.ErrorContains(t, err, "Init source image parser")
	})

	t.Run("source parser failed", func(t *testing.T) {
		remotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(ref string, insecure bool) (*remote.Remote, error) {
			return &remote.Remote{Ref: ref}, nil
		})
		defer remotePatches.Reset()

		calls := 0
		parserPatches := gomonkey.ApplyFunc(parser.New, func(remoter *remote.Remote, arch string) (*parser.Parser, error) {
			calls++
			if calls == 1 {
				return &parser.Parser{Remote: remoter}, nil
			}
			return nil, errors.New("source parser failed")
		})
		defer parserPatches.Reset()

		checker, err := New(Opt{Target: "target", Source: "source", ExpectedArch: "amd64"})
		require.Nil(t, checker)
		require.ErrorContains(t, err, "failed to create parser")
	})

	t.Run("success", func(t *testing.T) {
		remotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(ref string, insecure bool) (*remote.Remote, error) {
			return &remote.Remote{Ref: ref}, nil
		})
		defer remotePatches.Reset()

		parserPatches := gomonkey.ApplyFunc(parser.New, func(remoter *remote.Remote, arch string) (*parser.Parser, error) {
			return &parser.Parser{Remote: remoter}, nil
		})
		defer parserPatches.Reset()

		checker, err := New(Opt{Target: "target", Source: "source", ExpectedArch: "amd64"})
		require.NoError(t, err)
		require.NotNil(t, checker)
		require.NotNil(t, checker.targetParser)
		require.NotNil(t, checker.sourceParser)
	})
}

func TestCheck(t *testing.T) {
	t.Run("retry with http", func(t *testing.T) {
		checker := &Checker{
			Opt:          Opt{WorkDir: t.TempDir()},
			targetParser: &parser.Parser{Remote: &remote.Remote{Ref: "localhost:5000/test:latest"}},
		}

		calls := 0
		parsePatches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(p *parser.Parser, ctx context.Context) (*parser.Parsed, error) {
			calls++
			if calls == 1 {
				return nil, fmt.Errorf("Head https://registry/localhost:5000/v2/test/manifests/latest failed: %w", syscall.ECONNREFUSED)
			}
			return &parser.Parsed{Remote: p.Remote}, nil
		})
		defer parsePatches.Reset()

		outputPatches := gomonkey.ApplyMethod(reflect.TypeOf(&Checker{}), "Output", func(*Checker, context.Context, *parser.Parsed, string) error {
			return nil
		})
		defer outputPatches.Reset()

		manifestPatches := gomonkey.ApplyMethod(reflect.TypeOf(&rule.ManifestRule{}), "Validate", func(*rule.ManifestRule) error { return nil })
		defer manifestPatches.Reset()
		bootstrapPatches := gomonkey.ApplyMethod(reflect.TypeOf(&rule.BootstrapRule{}), "Validate", func(*rule.BootstrapRule) error { return nil })
		defer bootstrapPatches.Reset()
		filesystemPatches := gomonkey.ApplyMethod(reflect.TypeOf(&rule.FilesystemRule{}), "Validate", func(*rule.FilesystemRule) error { return nil })
		defer filesystemPatches.Reset()

		require.NoError(t, checker.Check(context.Background()))
		require.Equal(t, 2, calls)
		require.True(t, checker.targetParser.Remote.IsWithHTTP())
	})

	t.Run("non retryable error", func(t *testing.T) {
		checker := &Checker{
			Opt:          Opt{WorkDir: t.TempDir()},
			targetParser: &parser.Parser{Remote: &remote.Remote{Ref: "localhost:5000/test:latest"}},
		}

		parsePatches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(*parser.Parser, context.Context) (*parser.Parsed, error) {
			return nil, errors.New("parse failed")
		})
		defer parsePatches.Reset()

		err := checker.Check(context.Background())
		require.ErrorContains(t, err, "parse nydus image")
		require.False(t, checker.targetParser.Remote.IsWithHTTP())
	})
}

func TestCheckInternal(t *testing.T) {
	t.Run("source parse failed", func(t *testing.T) {
		checker := &Checker{
			Opt:          Opt{WorkDir: t.TempDir()},
			targetParser: &parser.Parser{Remote: &remote.Remote{Ref: "target"}},
			sourceParser: &parser.Parser{Remote: &remote.Remote{Ref: "source"}},
		}

		parsePatches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(p *parser.Parser, ctx context.Context) (*parser.Parsed, error) {
			if p.Remote.Ref == "source" {
				return nil, errors.New("source parse failed")
			}
			return &parser.Parsed{Remote: p.Remote}, nil
		})
		defer parsePatches.Reset()

		err := checker.check(context.Background())
		require.ErrorContains(t, err, "parse source image")
	})

	t.Run("output failed", func(t *testing.T) {
		checker := &Checker{
			Opt:          Opt{WorkDir: t.TempDir()},
			targetParser: &parser.Parser{Remote: &remote.Remote{Ref: "target"}},
		}

		parsePatches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(p *parser.Parser, ctx context.Context) (*parser.Parsed, error) {
			return &parser.Parsed{Remote: p.Remote}, nil
		})
		defer parsePatches.Reset()

		outputPatches := gomonkey.ApplyMethod(reflect.TypeOf(&Checker{}), "Output", func(*Checker, context.Context, *parser.Parsed, string) error {
			return errors.New("output failed")
		})
		defer outputPatches.Reset()

		err := checker.check(context.Background())
		require.ErrorContains(t, err, "output image information")
	})

	t.Run("rule validate failed", func(t *testing.T) {
		checker := &Checker{
			Opt:          Opt{WorkDir: t.TempDir()},
			targetParser: &parser.Parser{Remote: &remote.Remote{Ref: "target"}},
		}

		parsePatches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(p *parser.Parser, ctx context.Context) (*parser.Parsed, error) {
			return &parser.Parsed{Remote: p.Remote}, nil
		})
		defer parsePatches.Reset()

		outputPatches := gomonkey.ApplyMethod(reflect.TypeOf(&Checker{}), "Output", func(*Checker, context.Context, *parser.Parsed, string) error {
			return nil
		})
		defer outputPatches.Reset()

		manifestPatches := gomonkey.ApplyMethod(reflect.TypeOf(&rule.ManifestRule{}), "Validate", func(*rule.ManifestRule) error {
			return errors.New("manifest failed")
		})
		defer manifestPatches.Reset()

		err := checker.check(context.Background())
		require.ErrorContains(t, err, "validate manifest failed")
	})
}
