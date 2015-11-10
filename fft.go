//
// FFT based polynomial multiplication.
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to ringlwe, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

import (
	"unsafe"
)

type fftCtx struct {
	x1 [64][64]uint32
	y1 [64][64]uint32
	z1 [64][64]uint32
	t1 [64]uint32
}

// Reduction modulo p = 2^32 - 1.
// This is not a prime since 2^32-1 = (2^1+1)*(2^2+1)*(2^4+1)*(2^8+1)*(2^16+1).
// But since 2 is a unit in Z/pZ we can use it for computing FFTs in
// Z/pZ[X]/(X^(2^7)+1)

// Caution:
// We use a redundant representation where the integer 0 is represented both
// by 0 and 2^32-1.
// This approach follows the describtion from the paper:
// Joppe W. Bos, Craig Costello, Huseyin Hisil, and Kristin Lauter: Fast Cryptography in Genus 2
// EUROCRYPT 2013, Lecture Notes in Computer Science 7881, pp. 194-210, Springer, 2013.
// More specifically see: Section 3 related to Modular Addition/Subtraction.

// Compute: c = (a+b) mod (2^32-1)
// Let, t = a+b = t_1*2^32 + t0, where 0 <= t_1 <= 1, 0 <= t_0 < 2^32.
// Then t mod (2^32-1) = t0 + t1

// Yawning: Golang is so fucking stupid sometimes.  Like when I would kill to
// have macros.  Or something that converts a bool to an int that's does not
// involve either branches, or using "unsafe".  I should probably revisit this
// and provide a vectorized assembly implementation of the entire FFT multiply.

func boolToInt(b bool) uint32 {
	// Yes, unsafe.  Really.  There is no better way to do this, which is all
	// sorts of fucking braindamaged.
	return uint32(*(*byte)(unsafe.Pointer(&b)))
}

func modadd(a, b uint32) (c uint32) {
	t := a + b
	c = t + boolToInt(t < a)
	return
}

func modsub(a, b uint32) (c uint32) {
	c = (a - b) - boolToInt(b > a)
	return
}

func modmul(a, b uint32) (c uint32) {
	t := uint64(a) * uint64(b)
	c = modadd(uint32(t), (uint32(uint64(t) >> 32)))
	return
}

func modmuladd(c, a, b uint32) uint32 {
	t := uint64(a)*uint64(b) + uint64(c)
	c = modadd(uint32(t), (uint32(t >> 32)))
	return c
}

func div2(a uint32) (c uint32) {
	c = uint32((uint64(a) + uint64(uint32(0-((a)&1))&0xFFFFFFFF)) >> 1)
	return
}

func normalize(a uint32) (c uint32) {
	c = a + boolToInt(a == 0xFFFFFFFF)
	return c
}

func moddiv2(a uint32) (c uint32) {
	c = normalize(a)
	c = div2(c)
	return
}

func neg(a uint32) (c uint32) {
	c = 0xFFFFFFFF - a
	c = normalize(c)
	return
}

// Reverse the bits, approach from "Bit Twiddling Hacks"
// See: https://graphics.stanford.edu/~seander/bithacks.html
func reverse(x uint32) uint32 {
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1))
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2))
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4))
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8))
	return ((x >> 16) | (x << 16))
}

// Nussbaumer approach, see:
// H. J. Nussbaumer. Fast polynomial transform algorithms for digital convolution. Acoustics, Speech and
// Signal Processing, IEEE Transactions on, 28(2):205{215, 1980
// We followed the describtion from Knuth:
// D. E. Knuth. Seminumerical Algorithms. The Art of Computer Programming. Addison-Wesley, Reading,
// Massachusetts, USA, 3rd edition, 1997
// Exercise Exercise 4.6.4.59.

func naive(z, x, y *[64]uint32, n uint) {
	for i := uint(0); i < n; i++ {
		B := uint32(0)

		A := modmul(x[0], y[i])

		var j uint
		for j = 1; j <= i; j++ {
			A = modmuladd(A, x[j], y[i-j])
		}

		for k := uint(1); j < n; j, k = j+1, k+1 {
			B = modmuladd(B, x[j], y[n-k])
		}
		z[i] = modsub(A, B)
	}
}

func nussbaumerFFT(z []uint32, x []uint32, y []uint32, ctx *fftCtx) {
	X1 := &ctx.x1
	Y1 := &ctx.y1

	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			X1[i][j] = x[32*j+i]
			X1[i+32][j] = x[32*j+i]

			Y1[i][j] = y[32*j+i]
			Y1[i+32][j] = y[32*j+i]
		}
	}

	Z1 := &ctx.z1
	T1 := &ctx.t1

	for j := 4; j >= 0; j-- {
		jj := uint(j)
		for i := uint32(0); i < (1 << (5 - jj)); i++ {
			ssr := reverse(i)
			for t := uint32(0); t < (1 << jj); t++ {
				s := i
				sr := ssr >> (32 - 5 + jj)
				sr <<= jj
				s <<= (jj + 1)

				// X_i(w) = X_i(w) + w^kX_l(w) can be computed as
				// X_ij = X_ij - X_l(j-k+r)  for  0 <= j < k
				// X_ij = X_ij + X_l(j-k)    for  k <= j < r
				I := s + t
				L := s + t + (1 << jj)

				for a := sr; a < 32; a++ {
					T1[a] = X1[L][a-sr]
				}
				for a := uint32(0); a < sr; a++ {
					T1[a] = neg(X1[L][32+a-sr])
				}

				for a := 0; a < 32; a++ {
					X1[L][a] = modsub(X1[I][a], T1[a])
					X1[I][a] = modadd(X1[I][a], T1[a])
				}

				for a := sr; a < 32; a++ {
					T1[a] = Y1[L][a-sr]
				}
				for a := uint32(0); a < sr; a++ {
					T1[a] = neg(Y1[L][32+a-sr])
				}

				for a := 0; a < 32; a++ {
					Y1[L][a] = modsub(Y1[I][a], T1[a])
					Y1[I][a] = modadd(Y1[I][a], T1[a])
				}
			}
		}
	}

	for i := 0; i < 2*32; i++ {
		naive(&Z1[i], &X1[i], &Y1[i], 32)
	}

	for j := uint32(0); j <= 5; j++ {
		for i := uint32(0); i < (1 << (5 - j)); i++ {
			ssr := reverse(i)
			for t := uint32(0); t < (1 << j); t++ {
				s := i
				sr := (ssr >> (32 - 5 + j))
				sr <<= j
				s <<= (j + 1)

				A := s + t
				B := s + t + (1 << j)

				for a := 0; a < 32; a++ {
					T1[a] = modsub(Z1[A][a], Z1[B][a])
					T1[a] = moddiv2(T1[a])
					Z1[A][a] = modadd(Z1[A][a], Z1[B][a])
					Z1[A][a] = moddiv2(Z1[A][a])
				}

				// w^{-(r/m)s'} (Z_{s+t}(w)-Z_{s+t+2^j}(w))
				for a := uint32(0); a < 32-sr; a++ {
					Z1[B][a] = T1[a+sr]
				}
				for a := 32 - sr; a < 32; a++ {
					Z1[B][a] = neg(T1[a-(32-sr)])
				}
			}
		}
	}

	for i := 0; i < 32; i++ {
		z[i] = modsub(Z1[i][0], Z1[32+i][32-1])
		for j := 1; j < 32; j++ {
			z[32*j+i] = modadd(Z1[i][j], Z1[32+i][j-1])
		}
	}
}

func (f *fftCtx) multiply(z, x, y *[1024]uint32) {
	nussbaumerFFT(z[:], x[:], y[:], f)
}

func (f *fftCtx) add(z, x, y *[1024]uint32) {
	for i := 0; i < 1024; i++ {
		z[i] = modadd(x[i], y[i])
	}
}

func init() {
	// Validate the assumptions made regarding bool/unsafe, in case the
	// developers decide to torment me further in the future.
	if unsafe.Sizeof(true) != 1 {
		panic("sizeof(bool) != 1")
	}
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		panic("bool primitive type data format is unexpected.")
	}
}
