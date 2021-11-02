package network

import (
	"crypto/ed25519"

	"github.com/Arceliar/ironwood/types"
)

const (
	publicKeySize  = ed25519.PublicKeySize
	privateKeySize = ed25519.PrivateKeySize
	signatureSize  = ed25519.SignatureSize
)

type publicKey [publicKeySize]byte
type privateKey [privateKeySize]byte
type signature [signatureSize]byte

type crypto struct {
	secretKey types.SecretKey
	publicKey publicKey
}

func sign(key *types.SecretKey, message []byte) (sig signature) {
	var tmp [64]byte
	key.SignED25519(&tmp, message)
	copy(sig[:], tmp[:])
	return
}

func (key privateKey) equal(comparedKey privateKey) bool {
	return key == comparedKey
}

func (key *publicKey) verify(message []byte, sig *signature) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), message, sig[:])
}

func (key publicKey) equal(comparedKey publicKey) bool {
	return key == comparedKey
}

func (key publicKey) addr() types.Addr {
	return types.Addr(key[:])
}

func (c *crypto) init(secret types.SecretKey) {
	c.secretKey = secret
	copy(c.publicKey[:], secret.PK[:])
}
