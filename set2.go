package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
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

func newEcbOracle(blockSize int, hasPrefix bool) func(input []byte) []byte {
	unknownPlaintext := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownPlaintextBytes, _ := base64.StdEncoding.DecodeString(unknownPlaintext)

	seed := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(seed)

	key := make([]byte, blockSize)
	rng.Read(key)
	cipher, _ := aes.NewCipher(key)

	prefix := []byte{}
	if hasPrefix {
		prefix = make([]byte, rng.Intn(blockSize)*rng.Intn(blockSize))
		rng.Read(prefix)
	}

	return func(input []byte) []byte {
		appendedInput := append(prefix, append(input, unknownPlaintextBytes...)...)
		paddedInput := pkcs7Pad(appendedInput, cipher.BlockSize())
		return ecbEncrypt(paddedInput, cipher)
	}
}

func ecbOracleDetectBlockSize(oracle func(input []byte) []byte) (int, error) {
	blockSize := 8
	// 2 * 8 bytes
	craftedInput := "AAAAAAAAAAAAAAAA"
	in := []byte(craftedInput)
	// give up once we reach blocks of size 1024 without finding matching blocks
	for blockSize <= 1<<10 {
		paddedInput := make([]byte, len(in))
		copy(paddedInput, in)
		for padPrefix := 0; padPrefix < blockSize; padPrefix++ {
			out := oracle(paddedInput)
			// in case oracle's output was prefixed by a random length of bytes
			for i := 0; i < len(out)-2*blockSize; i += blockSize {
				if bytes.Equal(out[i:i+blockSize], out[i+blockSize:i+2*blockSize]) {
					return blockSize, nil
				}
			}
			paddedInput = append(paddedInput, 'A')
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
		panic("failed to detect block size")
	}

	prefixLen := findPrefixSize(oracle, blockSize)
	prefixPaddingBytes := make([]byte, blockSize-prefixLen%blockSize)
	prefixPaddedLen := prefixLen + len(prefixPaddingBytes)

	craftedPlaintext := make([]byte, 0)
	for i := 0; i < blockSize; i++ {
		craftedPlaintext = append(craftedPlaintext, 'A')
	}

	for i := prefixPaddedLen; i < len(ciphertext); i += blockSize {
		blockSolution := make([]byte, 0)

		for j := 0; j < blockSize; j++ {
			craftedPlaintext = craftedPlaintext[1:]
			known := append(craftedPlaintext, blockSolution...)

			bmap := make(map[string]byte)
			for k := 0; k < 256; k++ {
				mkey := oracle(append(prefixPaddingBytes, append(known, byte(k))...))[prefixPaddedLen:]
				bmap[string(mkey[:blockSize])] = byte(k)
			}

			craftedCiphertext := oracle(append(prefixPaddingBytes, craftedPlaintext...))
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
func (up *UserProfile) ParseQueryParams(params string) {
	v, _ := url.ParseQuery(params)

	uid, _ := strconv.Atoi(v.Get("uid"))
	up.UID = uid
	up.Email = v.Get("email")
	up.Role = v.Get("role")
}

// IsAdmin returns true if user is admin
func (up *UserProfile) IsAdmin() bool {
	return up.Role == "admin"
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

func ecbCutAndPaste() *UserProfile {
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
	up.ParseQueryParams(string(pt))
	return up
}

func findPrefixSize(oracle func(input []byte) []byte, blockSize int) int {
	prefixLenModBlockSize := findPrefixLengthModBlockSize(oracle, blockSize)
	prefixEndingBlock := findPrefixEndingBlock(oracle, blockSize)
	return (prefixEndingBlock * blockSize) + prefixLenModBlockSize
}

func findPrefixEndingBlock(oracle func(input []byte) []byte, blockSize int) int {
	outOne := oracle([]byte{})
	outTwo := oracle([]byte{'A'})
	for i := 0; i < len(outOne)/blockSize; i++ {
		if !bytes.Equal(
			outOne[i*blockSize:i*blockSize+blockSize],
			outTwo[i*blockSize:i*blockSize+blockSize]) {
			return i
		}
	}
	return -1
}

// Find the number of bytes of the prefix that overflow
// to the last block containing prefix bytes:
//
// Block 1    Block 2      Block 3
// PPPPPPPP | *PPP*AAAAA | AAAAAAAA => 3
func findPrefixLengthModBlockSize(oracle func(input []byte) []byte, blockSize int) int {
	craftedInput := make([]byte, 2*blockSize)
	for i := 0; i < len(craftedInput); i++ {
		craftedInput[i] = 'A'
	}

	for p := 0; p < blockSize; p++ {
		out := oracle(craftedInput)
		for i := 0; i < len(out)-2*blockSize; i += blockSize {
			if bytes.Equal(out[i:i+blockSize], out[i+blockSize:i+2*blockSize]) {
				return (blockSize - p) % blockSize
			}
		}
		craftedInput = append(craftedInput, 'A')
	}
	return -1
}

func encryptUserData(cipher cipher.Block, iv []byte, userData string) []byte {
	pre := "comment1=cooking%20MCs;userdata="
	post := ";comment2=%20like%20a%20pound%20of%20bacon"
	// escape special input characters
	r := strings.NewReplacer(";", `";"`, "=", `"="`)
	userData = r.Replace(userData)
	encodedUserData := fmt.Sprintf("%s%s%s", pre, userData, post)
	paddedEncodedUserData := pkcs7Pad([]byte(encodedUserData), cipher.BlockSize())
	return cbcEncrypt(paddedEncodedUserData, iv, cipher)
}

func decryptUserData(cipher cipher.Block, iv []byte, ciphertext []byte) (bool, error) {
	cpCiphertext := make([]byte, len(ciphertext))
	copy(cpCiphertext, ciphertext)

	tamperedCiphertext, err := bitflipCiphertext(cipher, iv, cpCiphertext, 48, ";admin=true;")
	if err != nil {
		return false, err
	}
	plaintext := pkcs7Unpad(cbcDecrypt(tamperedCiphertext, iv, cipher))
	return strings.Contains(string(plaintext), ";admin=true;"), nil
}

func bitflipCiphertext(cipher cipher.Block, iv, ciphertext []byte, start int, targetString string) ([]byte, error) {
	blockSize := cipher.BlockSize()
	startPrevBlock := start - blockSize

	if start < 0 {
		return nil, fmt.Errorf("starting position to bitflip cannot be negative")
	}

	if start >= len(ciphertext) {
		return nil, fmt.Errorf("starting position to bitflip cannot be out of bounds of ciphertext's length")
	}

	if ((start % blockSize) + len(targetString)) > blockSize {
		return nil, fmt.Errorf("target string cannot expand to more than a single block")
	}

	// prepend an empty block to the ciphertext if we need the target
	// to happen in the 1st block (of the original) ciphertext
	if startPrevBlock < 0 {
		ciphertext = append(make([]byte, blockSize), ciphertext...)
		start = start + blockSize
	}

	plaintext := pkcs7Unpad(cbcDecrypt(ciphertext, iv, cipher))

	// plaintext segment
	pt := plaintext[start : start+len(targetString)]
	// ciphertext segment
	ct := ciphertext[startPrevBlock:start]
	// target string segment
	is := []byte(targetString)[:]

	// xor the 3 segments so we come up with a new
	// tampered segment that will result in the desired
	// target string when xor'ed with the next block's
	// cipher decryption output
	tampered := xor(xor(pt, ct), is)

	copy(ciphertext[startPrevBlock:], tampered)
	return ciphertext, nil
}
