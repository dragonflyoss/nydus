// Ported from nerdctl project, copyright The nerdctl Authors.
// https://github.com/containerd/nerdctl/blob/31b4e49db76382567eea223a7e8562e0213ef05f/pkg/idutil/containerwalker/containerwalker.go#L53

package committer

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/containerd/containerd/v2/client"
	"github.com/sirupsen/logrus"
)

type Found struct {
	Container  client.Container
	Req        string // The raw request string. name, short ID, or long ID.
	MatchIndex int    // Begins with 0, up to MatchCount - 1.
	MatchCount int    // 1 on exact match. > 1 on ambiguous match. Never be <= 0.
}

type OnFound func(ctx context.Context, found Found) error

type ContainerWalker struct {
	Client  *client.Client
	OnFound OnFound
}

func NewContainerWalker(client *client.Client, onFound OnFound) *ContainerWalker {
	return &ContainerWalker{
		Client:  client,
		OnFound: onFound,
	}
}

// Walk walks containers and calls w.OnFound.
// Req is name, short ID, or long ID.
// Returns the number of the found entries.
func (w *ContainerWalker) Walk(ctx context.Context, req string) (int, error) {
	logrus.Debugf("walking containers with request: %s", req)
	if strings.HasPrefix(req, "k8s://") {
		return -1, fmt.Errorf("specifying \"k8s://...\" form is not supported (Hint: specify ID instead): %q", req)
	}

	filters := []string{
		fmt.Sprintf("id~=^%s.*$", regexp.QuoteMeta(req)),
	}

	containers, err := w.Client.Containers(ctx, filters...)
	if err != nil {
		return -1, err
	}

	matchCount := len(containers)
	for i, c := range containers {
		logrus.Debugf("found match for container ID: %s", c.ID())
		f := Found{
			Container:  c,
			Req:        req,
			MatchIndex: i,
			MatchCount: matchCount,
		}
		if e := w.OnFound(ctx, f); e != nil {
			return -1, e
		}
	}

	return matchCount, nil
}
