/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
)

type Signer struct {
	publicKey *rsa.PublicKey
}

func New(publicKey []byte) (*Signer, error) {
	block, _ := pem.Decode(publicKey)
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Signer{
		publicKey: key,
	}, nil
}

func (s *Signer) Verify(input io.Reader, signature []byte) error {
	h := sha256.New()
	_, err := io.Copy(h, input)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, h.Sum(nil), signature)
}
