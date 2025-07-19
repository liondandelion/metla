// ~=  GOSThopper  =~
// Kuznechik cipher, GOST R 34.12-2015
// Main: gosthp.go
//
// 02/01/2024
// Declarations for assembly low level functions on arm64.
// Actual code - in docipher_arm64.s file.
//
// Alexander Venedioukhin (https://dxdt.ru/)
// Free software, distribution unlimited.
//

package gosthp

//go:noescape
//go:nosplit
func DoEncrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8

//go:noescape
//go:nosplit
func DoEncryptCounter(nonce [16]uint8, block [16]uint8, rkeys [10][16]uint8) [16]uint8

//go:noescape
//go:nosplit
func DoDecrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8

// NOTE:
// For DoDecrypt() under rkeys inversed round keys are expected.
// To get inverse keys use - GetDecryptRoundKeys().
