package types

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"io"

	"filippo.io/edwards25519"
)

type SecretKey struct {
	L  edwards25519.Scalar
	R  [32]byte
	PK [32]byte
}

func NewSecretKeyFromSeedPK(seedpk *[64]byte) (sk SecretKey, err error) {
	h := sha512.Sum512(seedpk[:32])
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return
	}
	A := new(edwards25519.Point).ScalarBaseMult(s)

	// L|R|PK
	sk.L = *s
	copy(sk.R[:], h[32:])
	copy(sk.PK[:], A.Bytes())

	if !bytes.Equal(sk.PK[:], seedpk[32:]) {
		err = errors.New("public key side mismatch")
	}
	return
}

func NewSecretKeyFromLR(lr *[64]byte) (sk SecretKey, err error) {
	s, err := edwards25519.NewScalar().SetCanonicalBytes(lr[:32])
	if err != nil {
		return
	}
	A := new(edwards25519.Point).ScalarBaseMult(s)

	// L|R|PK
	sk.L = *s
	copy(sk.R[:], lr[32:])
	copy(sk.PK[:], A.Bytes())

	return
}

func (sk *SecretKey) SignED25519(signature *[64]byte, message []byte) {
	s := &sk.L
	prefix := sk.R[:]

	mh := sha512.New()
	mh.Write(prefix)
	mh.Write(message)
	messageDigest := make([]byte, 0, sha512.Size)
	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		return
	}

	R := new(edwards25519.Point).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(sk.PK[:])
	kh.Write(message)
	hramDigest := make([]byte, 0, sha512.Size)
	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		return
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	copy(signature[:32], R.Bytes())
	copy(signature[32:], S.Bytes())
}

func (sk *SecretKey) Public() crypto.PublicKey {
	publicKey := make([]byte, ed25519.PublicKeySize)
	copy(publicKey, sk.PK[:])
	return ed25519.PublicKey(publicKey)
}

func (sk *SecretKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed25519: cannot sign hashed message")
	}
	var sig [64]byte
	sk.SignED25519(&sig, message)
	return sig[:], nil
}
