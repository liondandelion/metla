// GOST-HP (GOSThopper)
//
//
// 20/01/2024
// "Pure" Go implementation of cipher block operations for platforms
// where no assembly-language variant provided.
// This is VERY SLOW but almost universal.
//
// Alexander Venedioukhin (https://dxdt.ru/)
// Free software, distribution unlimited.
//
//go:build !amd64 && !arm64
// +build !amd64,!arm64

package gosthp

func DoEncrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	var i, j, k int
	var ct, r [16]uint8
	ct = block
	// Encryption process follows.
	for i = 0; i < 9; i++ { // We have nine basic rounds.
		for k = range ct {
			ct[k] = ct[k] ^ rkeys[i][k] // XOR with current round key.
		}
		for k = range r {
			r[k] = LS_enc_lookup[0][ct[0]][k] // Prepare for lookup.
		}
		for j = 1; j <= 15; j++ {
			// There are 15 values from lookup table to XOR.
			// Calculate XOR with lookup table elements. Each element corresponds
			// to particular value of byte at current block position (ct[j]).
			for k = range r {
				r[k] = r[k] ^ LS_enc_lookup[j][ct[j]][k]
			}
		}
		ct = r
	}
	for k = range ct {
		ct[k] = ct[k] ^ rkeys[9][k]
	} // XOR with the last round key.

	return ct
}

func DoEncryptCounter(nonce [16]uint8, block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	var i, j, k int
	var ct, r [16]uint8
	ct = nonce
	// Encryption process follows.
	for i = 0; i < 9; i++ { // We have nine basic rounds.
		for k = range ct {
			ct[k] = ct[k] ^ rkeys[i][k] // XOR with current round key.
		}
		for k = range r {
			r[k] = LS_enc_lookup[0][ct[0]][k] // Prepare for lookup.
		}
		for j = 1; j <= 15; j++ {
			// There are 15 values from lookup table to XOR.
			// Calculate XOR with lookup table elements. Each element corresponds
			// to particular value of byte at current block position (ct[j]).
			for k = range r {
				r[k] = r[k] ^ LS_enc_lookup[j][ct[j]][k]
			}
		}
		ct = r
	}
	for k = range ct {
		ct[k] = ct[k] ^ rkeys[9][k]
	} // XOR with the last round key.
	for k = range ct {
		ct[k] = ct[k] ^ block[k]
	} // XOR with plain text.
	return ct
}

func DoDecrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	var i, j, k int
	var pt, r [16]uint8

	pt = block
	// First - apply inverse L using lookup table.
	for k = range r {
		r[k] = L_inv_lookup[0][pt[0]][k]
	}
	for j = 1; j <= 15; j++ {
		for k = range r {
			r[k] = r[k] ^ L_inv_lookup[j][pt[j]][k]
		}
	}
	pt = r

	for i = 9; i > 1; i-- {
		// XOR with current round key (inversed).
		for k = range pt {
			pt[k] = pt[k] ^ rkeys[i][k]
		}
		// Apply SL transformations using lookup table.
		for k = range r {
			r[k] = SL_dec_lookup[0][pt[0]][k]
		}
		for j = 1; j <= 15; j++ {
			for k = range r {
				r[k] = r[k] ^ SL_dec_lookup[j][pt[j]][k]
			}
		}
		pt = r
	}

	for k = range pt {
		pt[k] = pt[k] ^ rkeys[1][k]     // XOR with K_2
		pt[k] = Pi_inverse_table[pt[k]] // Inverse Pi
		pt[k] = pt[k] ^ rkeys[0][k]     // XOR with K_1
	}
	return pt // Plain text.
}
