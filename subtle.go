//
// 64 bit Subtle Comparisons
//
// To the extent possible under law, Yawning Angel waived all copyright
// and related or neighboring rights to bcns, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bcns

//
// These routines provide constant-time comparisons and other subtle operations
// analagous to the `crypto/subtle` package over 64 bit integers.
//

// Returns 1 if x != 0
// Returns 0 if x == 0
// x and y are arbitrary unsigned 64-bit integers
func ctIsNonZeroU64(x uint64) uint64 {
	return (x | -x) >> 63
}

// Returns 1 if x != y
// Returns 0 if x == y
// x and y are arbitrary unsigned 64-bit integers
func ctNeU64(x, y uint64) uint64 {
	return ((x - y) | (y - x)) >> 63
}

// Returns 1 if x == y
// Returns 0 if x != y
// x and y are arbitrary unsigned 64-bit integers
func ctEqU64(x, y uint64) uint64 {
	return 1 ^ ctNeU64(x, y)
}

// Returns 1 if x < y
// Returns 0 if x >= y
// x and y are arbitrary unsigned 64-bit integers
func ctLtU64(x, y uint64) uint64 {
	return (x ^ ((x ^ y) | ((x - y) ^ y))) >> 63
}

// Returns 1 if x > y
// Returns 0 if x <= y
// x and y are arbitrary unsigned 64-bit integers
func ctGtU64(x, y uint64) uint64 {
	return ctLtU64(y, x)
}

// Returns 1 if x <= y
// Returns 0 if x > y
// x and y are arbitrary unsigned 64-bit integers
func ctLeU64(x, y uint64) uint64 {
	return 1 ^ ctGtU64(x, y)
}

// Returns 1 if x >= y
// Returns 0 if x < y
// x and y are arbitrary unsigned 64-bit integers
func ctGeU64(x, y uint64) uint64 {
	return 1 ^ ctLtU64(x, y)
}

// Returns 0xFFFF..FFFF if bit != 0
// Returns            0 if bit == 0
func ctMaskU64(bit uint64) uint64 {
	return 0 - uint64(ctIsNonZeroU64(bit))
}

// Conditionally return x or y depending on whether bit is set
// Equivalent to: return bit ? x : y
// x and y are arbitrary 64-bit unsigned integers
// bit must be either 0 or 1.
func selectU64(x, y, bit uint64) uint64 {
	m := ctMaskU64(bit)
	return (x & m) | (y & (^m))
}

// Returns 0 if a >= b
// Returns 1 if a < b
// Where a and b are both 3-limb 64-bit integers.
func lessThanU192(a, b *[3]uint64) uint64 {
	var r, m uint64
	for i := 0; i < 3; i++ {
		r |= ctLtU64(a[i], b[i]) & (^m)
		m |= ctMaskU64(ctNeU64(a[i], b[i])) /* stop when a[i] != b[i] */
	}
	return r & 1
}
