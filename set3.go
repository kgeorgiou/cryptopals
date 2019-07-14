package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"log"
	mrand "math/rand"
)

func cbcPaddingOracle() (
	encryptRandomString func() ([]byte, []byte),
	paddingOracle func(iv, ciphertext []byte) bool) {

	key := make([]byte, 16)
	rand.Read(key)

	cipher, _ := aes.NewCipher(key)

	encryptRandomString = func() ([]byte, []byte) {
		pool := []string{
			"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
			"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
			"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
			"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
			"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
			"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
			"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
			"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
			"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
			"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
		}

		str := pool[mrand.Intn(len(pool))]

		strDecoded, _ := base64.StdEncoding.DecodeString(str)
		strPadded := pkcs7Pad(strDecoded, cipher.BlockSize())

		iv := make([]byte, 16)
		rand.Read(iv)

		return iv, cbcEncrypt(strPadded, iv, cipher)
	}

	paddingOracle = func(iv, ciphertext []byte) bool {
		plaintext := cbcDecrypt(ciphertext, iv, cipher)
		_, err := pkcs7Unpad(plaintext)
		return err == nil
	}

	return
}

func attackCBCPaddingOracle() []byte {
	getCiphertext, oracle := cbcPaddingOracle()
	iv, ct := getCiphertext()
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
					if j < blockSize - 1 || candidatesFound == lastBytePick {
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
