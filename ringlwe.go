//
// Ring Learning With Errors (Interface)
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package bcns implements a key exchange based on the Ring Learning With
// Errors Problem.  It is based heavily on the Public Domain implementation
// by Joppe W. Bos, Craig Costello, Michael Naehrig, and Douglas Stebila.
//
// For more information see: http://eprint.iacr.org/2014/599
//
package bcns

import (
	"crypto"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// PublicKeySize is the length of a Ring-LWE public key in bytes.
	PublicKeySize = 4096

	// PrivateKeySize is the length of a Ring-LWE private key in bytes.
	PrivateKeySize = 4096

	// RecDataSize is the length of the reconcilliation data in bytes.
	RecDataSize = 128

	// SharedSecretSize is the length of a Ring-LWE Shared Secret in bytes.
	SharedSecretSize = 128
)

var (
	// ErrInvalidPublicKeySize is the error returned when a public key blob
	// is an invalid length.
	ErrInvalidPublicKeySize = errors.New("rlwe: invalid public key length")

	// ErrInvalidRecDataSize is the error returned when a reconcilliation
	// data blob is an invalid length.
	ErrInvalidRecDataSize = errors.New("rlwe: invalid reconcilliation data length")
)

// PublicKey is a Ring-LWE public key.
type PublicKey struct {
	publicKey [1024]uint32
}

// FromBytes deserializes a Ring-LWE public key.
func (pub *PublicKey) FromBytes(b []byte) error {
	if len(b) != PublicKeySize {
		return ErrInvalidPublicKeySize
	}
	for i := range pub.publicKey {
		pub.publicKey[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return nil
}

// Bytes serializes a Ring-LWE public key.
func (pub *PublicKey) Bytes() []byte {
	ret := make([]byte, PublicKeySize)
	for i, v := range pub.publicKey {
		binary.LittleEndian.PutUint32(ret[i*4:], v)
	}
	return ret
}

// PrivateKey is a Ring-LWE private key.
type PrivateKey struct {
	privateKey [1024]uint32
}

// RecData is the Ring-LWE reconcilliation data.
type RecData struct {
	recData [16]uint64
}

// FromBytes deserializes a Ring-LWE reconcilliation data blob.
func (rec *RecData) FromBytes(b []byte) error {
	if len(b) != RecDataSize {
		return ErrInvalidRecDataSize
	}
	for i := range rec.recData {
		rec.recData[i] = binary.LittleEndian.Uint64(b[i*8:])
	}
	return nil
}

// Bytes serializes Ring-LWE reconcilliation data.
func (rec *RecData) Bytes() []byte {
	ret := make([]byte, RecDataSize)
	for i, v := range rec.recData {
		binary.LittleEndian.PutUint64(ret[i*8:], v)
	}
	return ret
}

// GenerateKeyPair returns a private/public key pair.  The private key is
// generated using the given reader which must return random data.
func GenerateKeyPair(r io.Reader) (*PrivateKey, *PublicKey, error) {
	pub := new(PublicKey)
	priv := new(PrivateKey)
	err := kexGenerateKeypair(r, &rlweARef, &priv.privateKey, &pub.publicKey)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// KeyExchangeAlice is the Initiator side of the Ring-LWE key exchange.
func KeyExchangeAlice(bobPk *PublicKey, aliceSk *PrivateKey, rec *RecData) []byte {
	var ss [16]uint64
	kexComputeKeyAlice(&bobPk.publicKey, &aliceSk.privateKey, &rec.recData, &ss)
	out := make([]byte, SharedSecretSize)
	for i := range ss {
		binary.LittleEndian.PutUint64(out[i*8:], ss[i])
		ss[i] = 0
	}
	return out
}

// KeyExchangeBob is the Responder side of the Ring-LWE key exchange.  The
// reconciliation data and shared secret are generated using the given reader
// which must return random data.
func KeyExchangeBob(r io.Reader, alicePk *PublicKey, bobSk *PrivateKey) (*RecData, []byte, error) {
	var ss [16]uint64
	rec := new(RecData)
	err := kexComputeKeyBob(r, &alicePk.publicKey, &bobSk.privateKey, &rec.recData, &ss)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, SharedSecretSize)
	for i := range ss {
		binary.LittleEndian.PutUint64(out[i*8:], ss[i])
		ss[i] = 0
	}
	return rec, out, nil
}

var _ crypto.PublicKey = (*PublicKey)(nil)
var _ crypto.PrivateKey = (*PrivateKey)(nil)
