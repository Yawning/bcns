//
// Ring Learning With Errors (Interface) integration tests
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestInterfaceIntegration(t *testing.T) {
	// Initiator side:
	//  1. Generate a key pair.
	aliceSk, alicePk, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("failed GenerateKeyPair(Alice): %v", err)
	}

	//  2. Serialize and transmit the public key.
	alicePkBlob := alicePk.Bytes()

	// Responder side:
	//  a. Generate a key pair.
	bobSk, bobPk, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("failed GenerateKeyPair(Bob): %v", err)
	}

	//  b. Deserialize the initiator's public key.
	bAlicePk := &PublicKey{}
	if err = bAlicePk.FromBytes(alicePkBlob); err != nil {
		t.Fatalf("failed PublicKey.FromBytes(Alice): %v", err)
	}

	//  c. Complete the handshake, generating rec data and the shared secret.
	recData, ssBob, err := KeyExchangeBob(rand.Reader, bAlicePk, bobSk)
	if err != nil {
		t.Fatalf("failed KeyExchangeBob(): %v", err)
	}

	//  d. Serialize and transmit the public key + recData.
	recDataBlob := recData.Bytes()
	bobPkBlob := bobPk.Bytes()

	//  3. Deserialize the public key + recData.
	aRecData := &RecData{}
	if err = aRecData.FromBytes(recDataBlob); err != nil {
		t.Fatalf("failed RecData.FromBytes(): %v", err)
	}
	aBobPk := &PublicKey{}
	if err = aBobPk.FromBytes(bobPkBlob); err != nil {
		t.Fatalf("failed PublicKey.FromBytes(bob): %v", err)
	}

	//  4. Complete the handshake, generating the shared secret.
	ssAlice := KeyExchangeAlice(aBobPk, aliceSk, aRecData)

	// Both Alice and Bob should have the same shared secret.  The
	// reconciliation process will fail with a probability less than
	// 2^-(2^-17).
	if !bytes.Equal(ssAlice, ssBob) {
		t.Fatalf("alice/bob shared secrets mismatch!")
	}
}
