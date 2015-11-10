//
// Random Number Generation
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
)

//
// Like the original code this was based on, use AES to derive all the
// random numbers needed, since using "cryto/rand" will be rather slow.
//
// To facilitate making the algorithm deterministic for testing, an
// io.Reader can be provided to the constructor, however all actual users
// should use a cryptographic entropy source.
//

type randCtx struct {
	s cipher.Stream
}

func newRandCtx(r io.Reader) (*randCtx, error) {
	var key [32]byte
	var iv [aes.BlockSize]byte

	// Use a random key/IV...
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return nil, err
	}

	// ...AES-256...
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	// ...CTR mode.  I would have used ChaCha20 here if I had vectorized my
	// implementation.  Oh well.
	ctx := &randCtx{s: cipher.NewCTR(block, iv[:])}
	return ctx, nil
}

func (c *randCtx) random32() uint32 {
	var b [4]byte
	c.s.XORKeyStream(b[:], b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func (c *randCtx) random64() uint64 {
	var b [8]byte
	c.s.XORKeyStream(b[:], b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func (c *randCtx) random192(r *[3]uint64) {
	var buf [24]byte
	c.s.XORKeyStream(buf[:], buf[:])
	r[0] = binary.LittleEndian.Uint64(buf[0:])
	r[1] = binary.LittleEndian.Uint64(buf[8:])
	r[2] = binary.LittleEndian.Uint64(buf[16:])
}
