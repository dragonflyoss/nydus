/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/label"
)

const (
	sep = ":"
)

var (
	emptyPassKeyChain = PassKeyChain{}
)

// PassKeyChain is user/pass based key chain
type PassKeyChain struct {
	Username string
	Password string
}

func FromBase64(str string) (PassKeyChain, error) {
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return emptyPassKeyChain, nil
	}
	pair := strings.Split(string(decoded), sep)
	if len(pair) != 2 {
		return emptyPassKeyChain, errors.New("invalid registry auth token")
	}
	return PassKeyChain{
		Username: pair[0],
		Password: pair[1],
	}, nil
}

func (kc PassKeyChain) ToBase64() string {
	if kc.Username == "" && kc.Password == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", kc.Username, kc.Password)))
}

// FromLabels find image pull username and secret from snapshot labels
// if username and secret is empty, we treat it as empty string
func FromLabels(labels map[string]string) (PassKeyChain, error) {
	return PassKeyChain{
		Username: labels[label.ImagePullUsername],
		Password: labels[label.ImagePullSecret],
	}, nil
}

func (kc PassKeyChain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return authn.FromConfig(authn.AuthConfig{
		Username: kc.Username,
		Password: kc.Password,
	}), nil
}
