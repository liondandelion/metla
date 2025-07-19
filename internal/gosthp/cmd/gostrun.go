package main

import (
	"crypto/cipher"
	"fmt"
	"gostrun/gosthp"
	//	"os"
	"bytes"
	"math/rand"
	"time"
)

func main() {

	// Test vectors.
	// Standard test key.
	var testK = [32]uint8{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	// Standard test plain text block and corresponding cipher text.
	var testPT = [16]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	var referenceCT = [16]uint8{0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30, 0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD}
	// Additional key, one bit changed testK.
	var testK1 = [32]uint8{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcf, 0xef}
	// Example key (non-standard).
	var exampleK = [32]uint8{0x17, 0x19, 0xca, 0xfe, 0x0c, 0x10, 0x03, 0x15, 0x2d, 0x19, 0x27, 0x13, 0x07, 0xab, 0x71, 0x67,
		0x1f, 0xe9, 0xa7, 0x31, 0x87, 0x15, 0x78, 0x61, 0x65, 0x03, 0x01, 0xef, 0x4a, 0xec, 0x9f, 0xf3}

	// Test vectors for GCM.
	var varK = []byte{0x31, 0x89, 0x9a, 0x7e, 0x1a, 0x03, 0x03, 0x51, 0xd2, 0x97, 0x79, 0x3b, 0x7f, 0xaf, 0xfe, 0x71,
		0xff, 0xe0, 0xca, 0x13, 0x42, 0x5e, 0x99, 0x77, 0x6b, 0xd3, 0xee, 0x11, 0xba, 0xc7, 0x92, 0x8f}

	var GCMNonce = []byte{0x3c, 0x81, 0x9d, 0x9a, 0x9b, 0xed, 0x08, 0x76, 0x15, 0x03, 0x0b, 0x65}
	var GCMExampleAD = []byte{'T', 'O', ':', ' ', 'S', 'e', 'a', 'p', 'o', 'r', 't', ',', ' ', 'a', 'g', 'e', 'n', 't', ' ', 'Z', 'o', 'r', 'k', 'a'}
	var GCMExampleADm = []byte{'T', 'O', ':', ' ', 'S', 'e', 'a', 'p', 'o', 'r', 't', ',', ' ', 'a', 'g', 'e', 'n', 't', ' ', 'D', 'a', 's', 'h', 'a'}
	var GCMExamplePT = []byte{'S', 'e', 'a', 'r', 'c', 'h', ' ', 't', 'h', 'e', ' ', 'b', 'i', 'g', ' ', 'w', 'h', 'i', 't', 'e', ' ', 's', 'h', 'i', 'p', '.'}
	// Test text for counter mode.
	var CounterModeExamplePT = "The hunter will softly and suddenly vanish away, and never be met with again."
	// Non-standard example plain text.
	var examplePT = [16]uint8{'S', 'e', 'a', 'r', 'c', 'h', ' ', 't', 'h', 'e', ' ', 's', 'h', 'i', 'p', '.'}
	// 16 blocks used in simple performance test.
	var randPT [16][16]uint8

	// For performance test we use non-standard test vector as a key - exampleK.
	rkeys := gosthp.StretchKey(exampleK)          // Generate round keys for encryption.
	decrkeys := gosthp.GetDecryptRoundKeys(rkeys) // Generate round keys for decryption.

	gosthp.InitCipher() // Generate lookup tables.

	fmt.Printf("\nGOST R 34.12-2015 test\n\n")
	fmt.Printf("| Standard test key:\n| %X\n| Standard test plain text:\n| %X\n\n", testK, testPT)
	fmt.Printf("---\n\n(1) Standard key vector\n")

	testCT := gosthp.Encrypt(testK, testPT)
	fmt.Printf("(1.1) Plain text:\t\t\t%X\n(1.2) Cipher text:\t\t\t%X - ", testPT, testCT)
	if testCT != referenceCT {
		fmt.Printf("FAILED! [Not equal to reference cipher text!]\n")
	} else {
		fmt.Printf("OK\n")
	}

	test2PT := gosthp.Decrypt(testK, testCT)
	fmt.Printf("(1.3) Plain text decrypted:\t\t%X - ", test2PT)

	if test2PT != testPT {
		fmt.Printf("FAILED! [PT != D(E(PT,K),K)]\n")
	} else {
		fmt.Printf("OK\n")
	}

	//os.Exit(1)

	fmt.Printf("---\n\n(1a) Incorrect key test\n")
	test2PT1 := gosthp.Decrypt(testK1, testCT)
	fmt.Printf("(1a.1) Plain text decrypted (key_1):\t%X - ", test2PT1)

	if test2PT1 != testPT {
		fmt.Printf("OK (different plain text)\n")
	} else {
		fmt.Printf("FAILED!\n")
	}

	fmt.Printf("\n\n(2) Example key and plain text vectors.\n\n")
	testCT = gosthp.DoEncrypt(examplePT, rkeys)
	fmt.Printf("(2.1)(Low level DoEncrypt) Cipher text:\t%X\n", testCT)

	test2PT = gosthp.DoDecrypt(testCT, decrkeys)
	fmt.Printf("(2.2)(Low level DoDecrypt) Plain text:\t")
	if examplePT != test2PT {
		fmt.Printf("- FAILED! [Not equal to reference plain text!]\n")
	} else {
		fmt.Printf("%s - OK\n", test2PT)
	}

	test3PT := gosthp.Decrypt(exampleK, testCT)
	fmt.Printf("(2.3)(Decrypt) Plain text:\t\t")
	if examplePT != test3PT {
		fmt.Printf(" - FAILED! [Not equal to reference plain text!]\n")
	} else {
		fmt.Printf("%s - OK\n", test3PT)
	}

	fmt.Printf("\n\n(3) Simple counter mode.\n\n")
	CMCipherText := gosthp.CM_Encrypt(0x1234567, exampleK, []uint8(CounterModeExamplePT))
	CMPlainText := gosthp.CM_Decrypt(0x1234567, exampleK, CMCipherText)

	fmt.Printf("Source PT:\n\t%s\nEncrypted:\n\t%0X\nDecrypted:\n\t%0X\n", CounterModeExamplePT, CMCipherText, CMPlainText)

	fcFlag := true

	if len(CMPlainText) != len([]uint8(CounterModeExamplePT)) {
		fcFlag = false
	} else {
		for l := range CMPlainText {
			if CMPlainText[l] != uint8(CounterModeExamplePT[l]) {
				fcFlag = false
				break
			}
		}
	}
	if fcFlag {
		fmt.Printf("\t(%s)\n", CMPlainText)
	}
	fmt.Printf("\n(3.1) Counter mode test - ")
	if !fcFlag {
		fmt.Printf("FAILED! [Not equal to source plain text!]\n")
	} else {
		fmt.Printf("OK\n")
	}

	fmt.Printf("\n---\n")

	fmt.Printf("\nTesting GCM (and cipher.Block interface) implementation.\n")

	kCipher, err := gosthp.NewCipher(varK)
	if err != nil {
		panic("NewCipher failed!\n")
	}

	kuznecGCM, err := cipher.NewGCM(kCipher)
	if err != nil {
		panic("NewGCM failed!\n")
	}

	GCMSealed := kuznecGCM.Seal(nil, GCMNonce, GCMExamplePT, GCMExampleAD)

	fmt.Printf("GCM:\n Plain text: %s\n Additional Data: %s\n Nonce: %X\n Encryption result (CT+Tag): %X\n", GCMExamplePT, GCMExampleAD, GCMNonce, GCMSealed)

	GCMOpened, err := kuznecGCM.Open(nil, GCMNonce, GCMSealed, GCMExampleAD)

	fmt.Printf(" GCM open result: %s - ", GCMOpened)
	if !bytes.Equal(GCMOpened, GCMExamplePT) {
		fmt.Printf("FAILED! [Not equal to reference plain text!]\n")
	} else {
		fmt.Printf("OK\n")
	}

	fmt.Printf(" GCM Manipulated AD check result: ")

	GCMOpened, err = kuznecGCM.Open(nil, GCMNonce, GCMSealed, GCMExampleADm)

	if err != nil {
		fmt.Printf(" [decryption failed] - OK (correct: must fail!)\n")
	} else {
		fmt.Printf(" [decrypted] - FAILED!\n")
	}

	fmt.Printf("\n---\n\nMeasuring speed.\nSimple block operations (DoEncrypt()/DoDecrypt()):\n")

	PRNG := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	for i := 0; i < 16; i++ {
		for t := range randPT[i] {
			randPT[i][t] = uint8(PRNG.Uint32())
		}
	}

	measureStart := time.Now()
	var counter int = 0

	for i := 0; i < 2300000; i++ {
		for t := range randPT {
			testCT = gosthp.DoEncrypt(randPT[t], rkeys)
			counter++
		}
	}

	elapsed := time.Since(measureStart)
	eSec := int(elapsed.Seconds())

	fmt.Printf(" Encryption - %d blocks (%d cbytes), time: %s", counter, counter*16, elapsed)
	if eSec > 0 {
		fmt.Printf(" (~%d MB/sec)\n", ((counter * 16) / eSec / 1048576))
	} else {
		fmt.Printf("\n")
	}

	fmt.Printf(" Block: %X\n\n", testCT)

	measureStart = time.Now()

	counter = 0

	for i := 0; i < 2300000; i++ {
		for t := range randPT {
			testCT = gosthp.DoDecrypt(randPT[t], decrkeys)
			counter++
		}
	}

	elapsed = time.Since(measureStart)
	eSec = int(elapsed.Seconds())

	fmt.Printf(" Decryption - %d blocks (%d bytes), time: %s", counter, counter*16, elapsed)
	if eSec > 0 {
		fmt.Printf(" (~%d MB/sec)\n", ((counter * 16) / eSec / 1048576))
	} else {
		fmt.Printf("\n")
	}

	fmt.Printf(" Block: %X\n\n", testCT)

	fmt.Printf("Kuznyechik-GCM:\n")
	LongBuffer := make([]byte, 1048576)
	LongResult := make([]byte, 1048576)

	for t := range LongBuffer {
		LongBuffer[t] = byte(PRNG.Uint32())
	}

	measureStart = time.Now()

	for i := 0; i < 100; i++ {

		for k := range GCMNonce {
			GCMNonce[k] = byte(PRNG.Uint32())
		}
		resBuf := kuznecGCM.Seal(nil, GCMNonce, LongBuffer, GCMExampleAD)
		LongResult, err = kuznecGCM.Open(nil, GCMNonce, resBuf, GCMExampleAD)
		if err != nil {
			fmt.Printf("GCM.Open Failed!\n")
		}
		if !bytes.Equal(LongBuffer, LongResult) {
			fmt.Printf("Failed: decrypted cipher text is not equal to source plain text!\n")
		}
	}

	elapsed = time.Since(measureStart)
	eSec = int(elapsed.Seconds())
	fmt.Printf(" 100 encrypt/decrypt operations on 10M buffer, time: %s", elapsed)
	if eSec > 0 {
		fmt.Printf(" (~%d MB/sec)\n", (200 / eSec))
	} else {
		fmt.Printf("\n")
	}

	fmt.Printf("\nDone!\n\n")

}
