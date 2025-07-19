// ~=  GOSThopper  =~
// Kuznechik cipher, GOST R 34.12-2015
// for arm64.
//
// Author: Alexander Venedioukhin, dxdt.ru
// Date: 02/01/2024
// Free software, distribution unlimited.

TEXT ·DoEncrypt(SB), $0
// Encrypts block.
		ADD		$8, RSP, R2						// Load address of PlainText into R2.
		VLD1	(R2), [V0.B16]					// Load PT into V0.
		ADD		$24, RSP, R3					// Load address of keys into R3.
		MOVD	·LS_enc_lookup_ptr(SB), R4		// Load global lookup table (cipher matrix) base address (R4).
		MOVD	R4, R5							// Save R4 (matrix ref.).
		MOVD	$(1<<12), R11					// Set constant offset (0x1000; hop for lookup table rows).
		MOVD	$10, R0							// R0 will count rounds (<10).

LOOP1:	SUB		$1, R0							// Loop counter.
		CBZ		R0, BREAK

		VLD1	(R3), [V1.B16]					// Load (next) key for current round into V3.
		VEOR	V1.B16, V0.B16, V0.B16			// XOR  (PT ^ Key).
		VMOV	V0.B[0], R7						// Extract byte at index 0 from V0 (PT).
		ADD		R7<<4, R4, R7					// Compute address of lookup element. 16 bytes per record in lookup table.
		VLD1	(R7), [V2.B16]					// Load element (128 bits or 16 bytes) into V2.
		
		ADD		R11, R4							// Add offset for next row in lookup table.
		VMOV	V0.B[1], R7						// (See above.)
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V4.B16]

		ADD		R11, R4
		VMOV	V0.B[2], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V5.B16]
		
		ADD		R11, R4
		VMOV	V0.B[3], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V6.B16]

		ADD		R11, R4
		VMOV	V0.B[4], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V7.B16]

		ADD		R11, R4
		VMOV	V0.B[5], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V8.B16]

		ADD		R11, R4
		VMOV	V0.B[6], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V9.B16]

		ADD		R11, R4
		VMOV	V0.B[7], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V10.B16]

		ADD		R11, R4
		VMOV	V0.B[8], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V11.B16]

		ADD		R11, R4
		VMOV	V0.B[9], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V12.B16]

		ADD		R11, R4
		VMOV	V0.B[10], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V13.B16]

		ADD		R11, R4
		VMOV	V0.B[11], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V14.B16]

		ADD		R11, R4
		VMOV	V0.B[12], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V15.B16]

		ADD		R11, R4
		VMOV	V0.B[13], R7
		ADD		R7<<4, R4, R7
		VLD1	(R7), [V16.B16]

		ADD		R11, R4
		VMOV	V0.B[14], R8
		ADD		R8<<4, R4, R8
		VLD1	(R8), [V17.B16]

		ADD		R11, R4
		VMOV	V0.B[15], R9
		ADD		R9<<4, R4, R9
		VLD1	(R9), [V18.B16]

		VEOR	V4.B16, V5.B16, V19.B16			// XOR every value fetched.
		VEOR	V6.B16, V7.B16, V20.B16
		VEOR	V8.B16, V9.B16, V21.B16
		VEOR	V10.B16, V11.B16, V22.B16
		VEOR	V12.B16, V13.B16, V23.B16
		VEOR	V14.B16, V15.B16, V24.B16
		VEOR	V16.B16, V17.B16, V25.B16
		VEOR	V18.B16, V2.B16, V2.B16
		VEOR	V19.B16, V2.B16, V2.B16
		VEOR	V20.B16, V2.B16, V2.B16
		VEOR	V21.B16, V2.B16, V2.B16
		VEOR	V22.B16, V2.B16, V2.B16
		VEOR	V23.B16, V2.B16, V2.B16
		VEOR	V24.B16, V2.B16, V2.B16
		VEOR	V25.B16, V2.B16, V0.B16

		ADD		$16, R3							// Next key address.
		MOVD	R5, R4							// Restore table index.
		B LOOP1
		//SUB		$1, R0							// Loop counter.
		//CBNZ	R0, LOOP1						// Loop if we have to.
		
BREAK:	VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16			// XOR with last key.
	
		ADD		$184, RSP, R2
		VST1	[V0.B16], (R2)					// Store result.
		
		RET

// Other functions here are built with code blocks similar to that seen above.
TEXT ·DoEncryptCounter(SB), $0
// Counter mode.
		ADD		$8, RSP, R2
		VLD1	(R2), [V0.B16]
		ADD		$24, RSP, R2
		VLD1	(R2), [V5.B16]
		ADD		$40, RSP, R3
		MOVD	·LS_enc_lookup_ptr(SB), R4
		MOVD	R4, R5
		MOVD	$(1<<12), R11
		MOVD	$9, R0
		
		
LOOP2:	VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]
		
		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		$16, R3
		VMOV	V2.B16, V0.B16
		MOVD	R5, R4
	
		SUB		$1, R0
		CBNZ	R0, LOOP2
		
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		VEOR	V0.B16, V5.B16, V5.B16
	
		ADD		$200, RSP, R2
		VST1	[V5.B16], (R2)
		
		RET

TEXT ·DoDecrypt(SB), $0-176
// Decryption. Less optimized.
		ADD		$8, RSP, R2
		VLD1	(R2), [V0.B16]
		MOVD	·L_inv_lookup_ptr(SB), R4		// Load global lookup table base address.
		MOVD	$(1<<12), R11
		
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]
		
		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		VMOV	V2.B16, V0.B16

		MOVD	·SL_dec_lookup_ptr(SB), R4		// Load global lookup table (cipher matrix) base address (R4).
		MOVD	R4, R5							// Save R4 (matrix ref.).
		MOVD	$8, R0							// R0 will count rounds.

		ADD		$168, RSP, R3					// We want last key here.

LOOP3:	VLD1	(R3), [V1.B16]					// Round key.
		VEOR	V1.B16, V0.B16, V0.B16
		VMOV	V0.B[0], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V2.B16]
		
		ADD		R11, R4
		VMOV	V0.B[1], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[2], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16
		
		ADD		R11, R4
		VMOV	V0.B[3], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[4], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[5], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[6], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[7], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[8], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[9], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[10], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[11], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[12], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[13], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[14], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		ADD		R11, R4
		VMOV	V0.B[15], R7
		LSL		$4, R7
		ADD		R4, R7
		VLD1	(R7), [V3.B16]
		VEOR	V3.B16, V2.B16, V2.B16

		SUB		$16, R3
		VMOV	V2.B16, V0.B16
		MOVD	R5, R4

		SUB		$1, R0
		CBNZ	R0, LOOP3
		
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V0.B16, V0.B16
		SUB		$16, R3
		
		MOVD	·Pi_inverse_table_ptr(SB), R4
		
		VMOV	V0.B[0], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[0]

		VMOV	V0.B[1], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[1]

		VMOV	V0.B[2], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[2]

		VMOV	V0.B[3], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[3]

		VMOV	V0.B[4], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[4]
		
		VMOV	V0.B[5], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[5]

		VMOV	V0.B[6], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[6]

		VMOV	V0.B[7], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[7]

		VMOV	V0.B[8], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[8]

		VMOV	V0.B[9], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[9]

		VMOV	V0.B[10], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[10]

		VMOV	V0.B[11], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[11]

		VMOV	V0.B[12], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[12]

		VMOV	V0.B[13], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[13]

		VMOV	V0.B[14], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[14]

		VMOV	V0.B[15], R7
		ADD		R4, R7
		VLD1	(R7), V2.B[15]
	
		VLD1	(R3), [V1.B16]
		VEOR	V1.B16, V2.B16, V2.B16
		
		ADD		$184, RSP, R2
		VST1	[V2.B16], (R2)
	
		RET

