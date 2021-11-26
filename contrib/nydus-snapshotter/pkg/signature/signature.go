/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package signature

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/signer"
)

type Verifier struct {
	signer *signer.Signer
	force  bool
}

func NewVerifier(publicKeyFile string, validateSignature bool) (*Verifier, error) {
	res := &Verifier{
		force: validateSignature,
	}
	if !validateSignature {
		return res, nil
	}
	if publicKeyFile == "" {
		return nil, errors.New("publicKeyFile is required")
	}
	if _, err := os.Stat(publicKeyFile); err != nil {
		return nil, fmt.Errorf("failed to find publicKeyFile %q", publicKeyFile)
	}
	publicKeyByte, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read from publicKeyFile %q", publicKeyFile)
	}
	sign, err := signer.New(publicKeyByte)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize signer")
	}
	res.signer = sign
	return res, nil
}

func (v *Verifier) Verify(label map[string]string, bootstrapFile string) error {
	signature, err := getFromLabel(label)
	if err != nil {
		return err
	}
	if signature == nil {
		if v.force {
			return errors.New("bootstrap signature is required when force validation")
		}
		return nil
	}

	if v.signer == nil {
		return nil
	}
	f, err := os.Open(bootstrapFile)
	if err != nil {
		return err
	}
	defer f.Close()
	return v.signer.Verify(f, signature)
}

func getFromLabel(labels map[string]string) ([]byte, error) {
	if s, ok := labels[label.Signature]; ok {
		res, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, nil
}

// func Verify(label map[string]string, bootstrapFile, publicKey string, force bool) error {
// 	signature, err := getFromLabel(label)
// 	if err != nil {
// 		return err
// 	}
// 	// if we found signature on image manifest, we should verify it
// 	if signature == nil {
// 		if force {
// 			return errors.New("bootstrap signature is required when force validation")
// 		}
// 		return nil
// 	}
//
// 	publicKeyByte, err := ioutil.ReadFile(publicKey)
// 	if err != nil {
// 		return err
// 	}
// 	sign, err := signer.New(publicKeyByte)
// 	if err != nil {
// 		return err
// 	}
// 	f, err := os.Open(bootstrapFile)
// 	if err != nil {
// 		return err
// 	}
// 	defer f.Close()
// 	return sign.Verify(f, signature)
// }
