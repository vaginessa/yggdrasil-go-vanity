package encrypted

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"

	"github.com/Arceliar/ironwood/encrypted/internal/e2c"
	"github.com/Arceliar/ironwood/types"
)

/********
 * util *
 ********/

func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func bytesPush(dest, source []byte, offset int) (newOffset int) {
	copy(dest[offset:], source)
	return offset + len(source)
}

func bytesPop(dest, source []byte, offset int) (newOffset int) {
	copy(dest[:], source[offset:])
	return offset + len(dest)
}

/******
 * ed *
 ******/

const (
	edPubSize  = 32
	edPrivSize = 64
	edSigSize  = 64
)

type edPub [edPubSize]byte
type edPriv [edPrivSize]byte
type edSig [edSigSize]byte

type edSec types.SecretKey

func edSign(msg []byte, priv *edSec) *edSig {
	var sig [64]byte
	((*types.SecretKey)(priv)).SignED25519(&sig, msg)
	return (*edSig)(&sig)
}

func edCheck(msg []byte, sig *edSig, pub *edPub) bool {
	return ed25519.Verify(pub[:], msg, sig[:])
}

func (pub *edPub) asKey() ed25519.PublicKey {
	return ed25519.PublicKey(pub[:])
}

func (pub *edPub) toBox() (*boxPub, error) {
	var c boxPub
	e, err := e2c.Ed25519PublicKeyToCurve25519(pub.asKey())
	if err != nil {
		return nil, err
	}
	copy(c[:], e)
	return &c, nil
}

func (sec *edSec) pub() *edPub {
	pub := new(edPub)
	copy(pub[:], sec.PK[:])
	return pub
}

func (sec *edSec) toBox() *boxPriv {
	var c boxPriv
	copy(c[:], sec.OrigL[:])
	return &c
}

/*******
 * box *
 *******/

const (
	boxPubSize    = 32
	boxPrivSize   = 32
	boxSharedSize = 32
	boxNonceSize  = 24
	boxOverhead   = box.Overhead
)

type boxPub [boxPubSize]byte
type boxPriv [boxPrivSize]byte
type boxShared [boxSharedSize]byte
type boxNonce [boxNonceSize]byte

func newBoxKeys() (pub boxPub, priv boxPriv) {
	bpub, bpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("failed to generate keys")
	}
	pub, priv = boxPub(*bpub), boxPriv(*bpriv)
	return
}

func getShared(out *boxShared, pub *boxPub, priv *boxPriv) {
	box.Precompute((*[32]byte)(out), (*[32]byte)(pub), (*[32]byte)(priv))
}

func boxOpen(out, boxed []byte, nonce uint64, shared *boxShared) ([]byte, bool) {
	n := nonceForUint64(nonce)
	return box.OpenAfterPrecomputation(out, boxed, (*[24]byte)(&n), (*[32]byte)(shared))
}

func boxSeal(out, msg []byte, nonce uint64, shared *boxShared) []byte {
	n := nonceForUint64(nonce)
	return box.SealAfterPrecomputation(out, msg, (*[24]byte)(&n), (*[32]byte)(shared))
}

// TODO we need to catch if nonce hits its max value and force a rekey
//  To that end, maybe we can use a smaller nonce size? or a vuint and reset on uint64 max?

func nonceForUint64(u64 uint64) boxNonce {
	var nonce boxNonce
	slice := nonce[boxNonceSize-8:]
	binary.BigEndian.PutUint64(slice, u64)
	return nonce
}
