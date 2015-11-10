//
// Ring LWE Key Exchange
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

import (
	"io"
)

// Generate keypair for RLWE KEX
//  - input: parameters: a
//  - output: private key s, public key b
func kexGenerateKeypair(r io.Reader, a *[1024]uint32, s *[1024]uint32, b *[1024]uint32) error {
	var e [1024]uint32
	var fft fftCtx

	rand, err := newRandCtx(r)
	if err != nil {
		return err
	}

	sample(s, rand)
	sample(&e, rand)
	keyGen(b, a, s, &e, &fft)
	// Scrub e, fft, rand?
	return nil
}

// Alice's shared key computation for RLWE KEX
//  - input: Bob's public key b, Alice's private key s, reconciliation data c
//  - output: shared secret k
func kexComputeKeyAlice(b, s *[1024]uint32, c *[16]uint64, k *[16]uint64) {
	var w [1024]uint32
	var fft fftCtx

	fft.multiply(&w, b, s)
	rec(k, &w, c)
	// Scrub w, fft?
}

// Bob's shared key computation for RLWE KEX
//  - input: Alice's public key b, Bob's private key s
//  - output: reconciliation data c, shared secret k
func kexComputeKeyBob(r io.Reader, b, s *[1024]uint32, c, k *[16]uint64) error {
	var v [1024]uint32
	var eprimeprime [1024]uint32
	var fft fftCtx

	rand, err := newRandCtx(r)
	if err != nil {
		return err
	}

	sample(&eprimeprime, rand)
	keyGen(&v, b, s, &eprimeprime, &fft)
	crossround2(c, &v, rand)
	round2(k, &v)
	// Scrub v, eprimeprime, fft, rand?
	return nil
}
