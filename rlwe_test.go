//
// Ring LWE integration tests/benchmarks
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func validateSharedSecret(a, b *[16]uint64) error {
	for i, v := range b {
		if a[i] != v {
			return fmt.Errorf("shared secret mismatch: [%d]: %v != %v", i, a[i], v)
		}
	}
	return nil
}

func TestKexComputeKeyAliceBob(t *testing.T) {
	var skAlice, pkAlice [1024]uint32
	err := kexGenerateKeypair(rand.Reader, &rlweARef, &skAlice, &pkAlice)
	if err != nil {
		t.Fatalf("alice: kexGenerateKeypair failed: %v", err)
	}

	var skBob, pkBob [1024]uint32
	err = kexGenerateKeypair(rand.Reader, &rlweARef, &skBob, &pkBob)
	if err != nil {
		t.Fatalf("alice: kexGenerateKeypair failed: %v", err)
	}

	var recData, sBob [16]uint64
	err = kexComputeKeyBob(rand.Reader, &pkAlice, &skBob, &recData, &sBob)
	if err != nil {
		t.Fatalf("bob: kexComputeKeyBob failed: %v", err)
	}

	var sAlice [16]uint64
	kexComputeKeyAlice(&pkBob, &skAlice, &recData, &sAlice)
	if err = validateSharedSecret(&sAlice, &sBob); err != nil {
		t.Fatalf("%v", err)
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	var skAlice, pkAlice [1024]uint32
	for i := 0; i < b.N; i++ {
		err := kexGenerateKeypair(rand.Reader, &rlweARef, &skAlice, &pkAlice)
		if err != nil {
			b.Fatalf("alice: kexGenerateKeypair failed: %v", err)
		}
	}
}

func BenchmarkKexAlice(b *testing.B) {
	var skAlice, pkAlice [1024]uint32
	for i := 0; i < b.N; i++ {
		err := kexGenerateKeypair(rand.Reader, &rlweARef, &skAlice, &pkAlice)
		if err != nil {
			b.Fatalf("alice: kexGenerateKeypair failed: %v", err)
		}

		b.StopTimer()
		var skBob, pkBob [1024]uint32
		err = kexGenerateKeypair(rand.Reader, &rlweARef, &skBob, &pkBob)
		if err != nil {
			b.Fatalf("alice: kexGenerateKeypair failed: %v", err)
		}

		var recData, sBob [16]uint64
		err = kexComputeKeyBob(rand.Reader, &pkAlice, &skBob, &recData, &sBob)
		if err != nil {
			b.Fatalf("bob: kexComputeKeyBob failed: %v", err)
		}
		b.StartTimer()

		var sAlice [16]uint64
		kexComputeKeyAlice(&pkBob, &skAlice, &recData, &sAlice)

		b.StopTimer()
		if err = validateSharedSecret(&sAlice, &sBob); err != nil {
			b.Fatalf("%v", err)
		}
		b.StartTimer()
	}
}

func BenchmarkKexBob(b *testing.B) {
	var skAlice, pkAlice [1024]uint32
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		err := kexGenerateKeypair(rand.Reader, &rlweARef, &skAlice, &pkAlice)
		if err != nil {
			b.Fatalf("alice: kexGenerateKeypair failed: %v", err)
		}

		b.StartTimer()
		var skBob, pkBob [1024]uint32
		err = kexGenerateKeypair(rand.Reader, &rlweARef, &skBob, &pkBob)
		if err != nil {
			b.Fatalf("alice: kexGenerateKeypair failed: %v", err)
		}

		var recData, sBob [16]uint64
		err = kexComputeKeyBob(rand.Reader, &pkAlice, &skBob, &recData, &sBob)
		if err != nil {
			b.Fatalf("bob: kexComputeKeyBob failed: %v", err)
		}
		b.StopTimer()

		var sAlice [16]uint64
		kexComputeKeyAlice(&pkBob, &skAlice, &recData, &sAlice)
		if err = validateSharedSecret(&sAlice, &sBob); err != nil {
			b.Fatalf("%v", err)
		}
	}
}
