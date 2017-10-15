package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

func pkcs7Pad(input []byte, k int) []byte {
	if !(k > 1) {
		panic("k must be greater than one - RFC5652")
	}
	if !(k < 256) {
		panic("this padding method is well defined if and only if k is less than 256 - RFC5652")
	}

	lth := len(input)
	paddingOctet := k - lth%k
	for i := 0; i < paddingOctet; i++ {
		input = append(input, byte(paddingOctet))
	}
	return input
}

func pkcs7Unpad(input []byte) []byte {
	if len(input) < 2 {
		panic("invalid PKCS#7 padding: input too short - RFC5652")
	}
	paddingOctet := input[len(input)-1]
	var count int
	for i := len(input) - 1; i >= 0 && i >= len(input)-int(paddingOctet); i-- {
		if input[i] != paddingOctet {
			panic("invalid PKCS#7 padding: padding octets mismatch - RFC5652")
		}
		count++
	}
	if count != int(paddingOctet) {
		panic("invalid PKCS#7 padding: missing padding bytes - RFC5652")
	}
	return input[:len(input)-int(paddingOctet)]
}

func ecbEncrypt(input []byte, cipher cipher.Block) []byte {
	blockSize := cipher.BlockSize()
	if len(input)%blockSize != 0 {
		panic("input length is not divisible by block size")
	}
	res := make([]byte, len(input))
	for i := 0; i < len(input); i += blockSize {
		cipher.Encrypt(res[i:i+blockSize], input[i:i+blockSize])
	}
	return res
}

func cbcEncrypt(plaintext, iv []byte, cipher cipher.Block) []byte {
	res := []byte{}
	blockSize := cipher.BlockSize()
	prevCiphertextBlock := iv
	for i := 0; i < len(plaintext); i += blockSize {
		currPlaintextBlock := plaintext[i : i+blockSize]
		xord := xor(prevCiphertextBlock, currPlaintextBlock)
		currCiphertextBlock := ecbEncrypt(xord, cipher)
		res = append(res, currCiphertextBlock...)
		prevCiphertextBlock = currCiphertextBlock
	}
	return res
}

func cbcDecrypt(ciphertext, iv []byte, cipher cipher.Block) []byte {
	res := []byte{}
	blockSize := cipher.BlockSize()
	decryptedCipher := ecbDecrypt(ciphertext, cipher)

	prevCipherBlock := iv
	for i := 0; i < len(decryptedCipher); i += blockSize {
		currDecryptedCipherBlock := decryptedCipher[i : i+blockSize]
		plaintextBlock := xor(prevCipherBlock, currDecryptedCipherBlock)
		res = append(res, plaintextBlock...)
		prevCipherBlock = ciphertext[i : i+blockSize]
	}
	return res
}

func encryptionOracle(input []byte) []byte {
	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	numBytesBefore := 5 + rng.Intn(6)
	numBytesAfter := 5 + rng.Intn(6)

	bytesBefore := make([]byte, numBytesBefore)
	rng.Read(bytesBefore)
	bytesAfter := make([]byte, numBytesAfter)
	rng.Read(bytesAfter)

	input = append(bytesBefore, input...)
	input = append(input, bytesAfter...)

	key := make([]byte, 16)
	rng.Read(key)
	cipher, _ := aes.NewCipher(key)
	input = pkcs7Pad(input, cipher.BlockSize())

	if rng.Intn(2) == 0 {
		iv := make([]byte, 16)
		rand.Read(iv)
		return cbcEncrypt(input, iv, cipher)
	}
	return ecbEncrypt(input, cipher)
}

func ecbOracle(input []byte) []byte {
	unknownBytes, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	input = append(input, unknownBytes...)
	key := []byte("0123456789abcdef")
	cipher, _ := aes.NewCipher(key)
	input = pkcs7Pad(input, cipher.BlockSize())
	return ecbEncrypt(input, cipher)
}

func ecbOracleDetectBlockSize(oracle func(input []byte) []byte) (int, error) {
	blockSize := 1
	craftedInput := "AA"
	in := []byte(craftedInput)
	// give up once we reach blocks of size 1024 without finding matching blocks
	for blockSize <= 1<<10 {
		out := oracle(in)
		if bytes.Equal(out[:blockSize], out[blockSize:2*blockSize]) {
			return blockSize, nil
		}
		in = append(in, []byte(craftedInput)...)
		blockSize++
	}
	return -1, fmt.Errorf("not ECB, probably - can't detect block size")
}

func ecbOraclePaddingAttack(oracle func(input []byte) []byte) []byte {
	ciphertext := oracle([]byte{})
	plaintext := make([]byte, 0)
	blockSize, err := ecbOracleDetectBlockSize(oracle)
	if err != nil {
		panic("oracle does not operate in ECB mode")
	}

	craftedPlaintext := make([]byte, 0)
	for i := 0; i < blockSize; i++ {
		craftedPlaintext = append(craftedPlaintext, 'A')
	}

	for i := 0; i < len(ciphertext); i += blockSize {
		blockSolution := make([]byte, 0)

		for j := 0; j < blockSize; j++ {
			craftedPlaintext = craftedPlaintext[1:]
			known := append(craftedPlaintext, blockSolution...)

			bmap := make(map[string]byte)
			for k := 0; k < 256; k++ {
				mkey := oracle(append(known, byte(k)))
				bmap[string(mkey[:blockSize])] = byte(k)
			}

			craftedCiphertext := oracle(craftedPlaintext)
			byteSolution, _ := bmap[string(craftedCiphertext[i:i+blockSize])]
			blockSolution = append(blockSolution, byteSolution)
		}
		craftedPlaintext = blockSolution
		plaintext = append(plaintext, blockSolution...)
	}
	return plaintext
}

// UserProfile for Challenge 13
type UserProfile struct {
	Email string `json:"email"`
	UID   int    `json:"uid"`
	Role  string `json:"role"`
}

// Encode encodes a UserProfile struct to url query params format
func (up *UserProfile) Encode() string {
	return "email=" + up.Email + "&uid=" + strconv.Itoa(up.UID) + "&role=" + up.Role
}

// ParseQueryParams parses url query encoded params to a UserProfile struct
func (up *UserProfile) ParseQueryParams(params string) string {
	v, _ := url.ParseQuery(params)

	uid, _ := strconv.Atoi(v["uid"][0])
	up.UID = uid
	up.Email = v["email"][0]
	up.Role = v["role"][0]

	upJSON, err := json.Marshal(up)
	if err != nil {
		panic("can't marshal UserProfile to JSON")
	}
	return string(upJSON)
}

func profileFor(email string) string {
	// Replace control metacharacters: [&=] -> _
	re := regexp.MustCompile(`[&=]`)
	email = re.ReplaceAllString(email, "_")

	profile := UserProfile{
		email,
		10,
		"user",
	}
	return profile.Encode()
}

func ecbCutAndPaste() string {
	key := []byte("0123456789abcdef")
	cipher, _ := aes.NewCipher(key)
	blockSize := cipher.BlockSize()

	profile := profileFor("eve@AAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0bAAA")
	ct := ecbEncrypt(pkcs7Pad([]byte(profile), blockSize), cipher)
	/*
		email=eve@AAAAAA
		adminXXXXXXXXXXX <- artificial padding
		AAA&uid=10&role=
		userPPPPPPPPPPPP <- legit padding
	*/

	nt := []byte{}
	nt = append(nt, ct[:blockSize]...)
	nt = append(nt, ct[blockSize:2*blockSize]...) // cut
	nt = append(nt, ct[2*blockSize:3*blockSize]...)
	nt = append(nt, ct[blockSize:2*blockSize]...) // paste
	/*
		email=eve@AAAAAA <- crafted 1st block
		adminXXXXXXXXXXX <- crafted 2nd block, with artificial PKCS7 padding
		AAA&uid=10&role= <- partly crafted 3rd block to push "role=" at the end of the block
		adminXXXXXXXXXXX <- crafted 2nd block, with artificial PKCS7 padding
	*/
	pt := pkcs7Unpad(ecbDecrypt(nt, cipher))

	up := new(UserProfile)
	upJSON := up.ParseQueryParams(string(pt))
	return upJSON
}
