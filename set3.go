package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func cbcPaddingOracle() (
	encrypt func(plaintext string) ([]byte, []byte),
	oracle func(iv, ciphertext []byte) bool) {

	key := make([]byte, 16)
	rand.Read(key)

	cipher, _ := aes.NewCipher(key)

	encrypt = func(plaintext string) ([]byte, []byte) {
		strDecoded, _ := base64.StdEncoding.DecodeString(plaintext)
		strPadded := pkcs7Pad(strDecoded, cipher.BlockSize())

		iv := make([]byte, 16)
		rand.Read(iv)

		return iv, cbcEncrypt(strPadded, iv, cipher)
	}

	oracle = func(iv, ciphertext []byte) bool {
		plaintext := cbcDecrypt(ciphertext, iv, cipher)
		_, err := pkcs7Unpad(plaintext)
		return err == nil
	}

	return
}

func attackCBCPaddingOracle(iv, ct []byte, oracle func(iv, ciphertext []byte) bool) []byte {
	blockSize := len(iv)

	pt := make([]byte, len(ct))
	foundBytes := make([]byte, len(ct))

	ct = append(iv, ct...)

	// Last byte of block has a chance of yielding valid paddings
	// for 2 different byte values: for 0x01 as expected, but also
	// a value N that, by chance, matches the N-1 bytes before it.
	// Example:
	// 1. 0xff ... 0x03 0x03 0x01
	// 2. 0xff ... 0x03 0x03 0x03
	lastBytePick := 1

	for i := 0; i <= len(ct)-2*blockSize; i += blockSize {

		c1 := ct[i : i+blockSize]
		c2 := ct[i+blockSize : i+2*blockSize]

		for j := blockSize - 1; j >= 0; j-- {
			padByte := byte(blockSize - j)
			c1Byte := c1[j]
			candidatesFound := 0

			found := false
			for candidateByte := 0; !found && candidateByte < 256; candidateByte++ {
				c1[j] = byte(candidateByte)
				isPaddingValid := oracle(c1, c2)
				if isPaddingValid {
					pt[i+j] = byte(padByte) ^ byte(candidateByte) ^ c1Byte
					foundBytes[i+j] = byte(candidateByte)

					candidatesFound++
					if j < blockSize-1 || candidatesFound == lastBytePick {
						found = true
					}
				}
			}

			if !found {
				if lastBytePick == 2 {
					// Should never happen
					log.Printf("couldn't find byte for pad byte %d", padByte)
					log.Printf("partial plaintext: %s", pt)
					return nil
				}
				// Restore corrupted byte
				c1[j] = c1Byte
				// Start from last byte again
				j = blockSize
				// Flag to lastBytePick the 2nd byte value, in the next tun,
				// that will also yield a valid padding, since this one was, by chance, a dead end
				lastBytePick++
				continue
			}

			// Next padding byte to fill the end of c1
			nextPadByte := padByte + 1
			// Make sure the postfix of current block is filled with the padding byte we
			// we are going to test for next
			for k := 1; int(nextPadByte) <= blockSize && byte(k) < nextPadByte; k++ {
				c1[blockSize-k] = (byte(k) ^ foundBytes[i+blockSize-k]) ^ byte(nextPadByte)
			}
		}
	}

	return pt
}

func ctrEncrypt(input, nonce []byte, cipher cipher.Block) ([]byte, error) {
	blockSize := cipher.BlockSize()
	plaintext := make([]byte, len(input))

	// need nonce size to be equal to half the block size
	// e.g. need 8 bytes nonce for 16 bytes block size
	if len(nonce) != blockSize/2 {
		return nil, fmt.Errorf("invalid nonce: wrong byte length")
	}

	// first half bytes: nonce
	// second half bytes: counter
	nonceCounter := make([]byte, blockSize)
	copy(nonceCounter, nonce)

	increaseCounter := func(counter []byte) {
		for i := 0; i < len(counter); i++ {
			counter[i]++
			if counter[i] != 0 {
				return
			}
		}
	}

	for i := 0; i < len(input); i += blockSize {
		// nonce + counter (both in Little Endian)
		xorWith := make([]byte, blockSize)
		cipher.Encrypt(xorWith, nonceCounter)
		copy(plaintext[i:], xor(input[i:], xorWith))

		// counter bytes are in 2nd half, in Little Endianess
		increaseCounter(nonceCounter[blockSize/2:])
	}

	return plaintext, nil
}

var ctrDecrypt = ctrEncrypt
