// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

func loadRsaPrivateKey(privateKeyFile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pk, ok := k.(*rsa.PrivateKey); ok {
		return pk, nil
	}
	return nil, errors.New("failed to load rsa private key")
}

func calculateDigest(input io.Reader) ([]byte, error) {
	h := sha256.New()
	_, err := io.Copy(h, input)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func Sign(privateKeyFile string, input io.Reader) ([]byte, error) {
	pk, err := loadRsaPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	digestBytes, err := calculateDigest(input)
	if err != nil {
		return nil, err
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digestBytes)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(signature)), nil
}

func SignFile(privateKeyFile, filePath string) ([]byte, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, errors.Wrap(err, "open bootstrap file")
	}

	return Sign(privateKeyFile, file)
}
