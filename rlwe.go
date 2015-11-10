//
// Ring Learning with Errors
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

// Yawning: Only the constant time variation of the code is implemented.
// If people want the non-constant time version, they can do it themselves.

func getbit(a []uint64, x int) uint64 {
	return (a[(x)/64] >> uint64((x)%64)) & 1
}

// We assume that e contains two random bits in the two
// least significant positions.
func dbl(in uint32, e int32) uint64 {
	// sample uniformly from [-1, 0, 0, 1]
	// Hence, 0 is sampled with twice the probability of 1
	e = (((e >> 1) & 1) - (int32(e & 1)))
	return uint64((uint64(in) << uint64(1)) - uint64(e))
}

func singleSample(in *[3]uint64) uint32 {
	index := uint64(0)
	for i := uint64(0); i < 52; i++ {
		index = selectU64(index, i, lessThanU192(in, &rlweTable[i]))
	}
	return uint32(index)
}

func sample(s *[1024]uint32, rand *randCtx) {
	for i := 0; i < 16; i++ {
		r := rand.random64()
		for j := 0; j < 64; j++ {
			var rnd [3]uint64
			var m, t uint32
			rand.random192(&rnd)
			m = uint32(r & 1)
			r >>= 1
			s[i*64+j] = singleSample(&rnd)
			t = 0xFFFFFFFF - s[i*64+j]
			s[i*64+j] = uint32(selectU64(uint64(t), uint64(s[i*64+j]), ctEqU64(uint64(m), 0)))
		}
	}
}

func round2(out *[16]uint64, in *[1024]uint32) {
	for i := range out {
		out[i] = 0
	}
	for i := 0; i < 1024; i++ {
		inI := uint64(in[i])
		b := ctGeU64(inI, 1073741824) & ctLeU64(inI, 3221225471)
		out[i/64] |= b << uint64(i%64)
	}
}

func crossround2(out *[16]uint64, in *[1024]uint32, rand *randCtx) {
	for i := range out {
		out[i] = 0
	}
	for i := 0; i < 64; i++ {
		e := rand.random32()
		for j := 0; j < 16; j++ {
			dd := dbl(in[i*16+j], int32(e))
			e >>= 2
			b := (ctGeU64(dd, 2147483648) & ctLeU64(dd, 4294967295)) |
				(ctGeU64(dd, 6442450942) & ctLeU64(dd, 8589934590))
			out[(i*16+j)/64] |= (b << uint64((i*16+j)%64))
		}
	}
}

func rec(out *[16]uint64, w *[1024]uint32, b *[16]uint64) {
	for i := range out {
		out[i] = 0
	}
	for i := 0; i < 1024; i++ {
		coswi := (uint64(w[i])) << 1
		B := (ctEqU64(getbit(b[:], i), 0) & ctGeU64(coswi, 3221225472) & ctLeU64(coswi, 7516192766)) |
			(ctEqU64(getbit(b[:], i), 1) & ctGeU64(coswi, 1073741824) & ctLeU64(coswi, 5368709118))
		out[i/64] |= (B << uint64(i%64))
	}
}

func keyGen(out, a, s, e *[1024]uint32, ctx *fftCtx) {
	ctx.multiply(out, a, s)
	ctx.add(out, out, e)
}
