// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Original code from: https://github.com/FiloSottile/age/blob/bbab440e198a4d67ba78591176c7853e62d29e04/internal/age/ssh.go

package e2c

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

func Ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func Ed25519SecretKeyLToCurve25519(a *edwards25519.Scalar) []byte {
	return a.Bytes()
}

func Ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) ([]byte, error) {
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}
