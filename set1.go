package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math"
	"math/bits"
	"unicode/utf8"
)

func hexToBase64(hexString string) string {
	decodedHex, err := hex.DecodeString(hexString)
	if err != nil {
		panic(err)
	}
	// Easter egg
	log.Printf("%s", decodedHex)
	result := base64.StdEncoding.EncodeToString(decodedHex)
	return result
}

func xor(input []byte, key []byte) []byte {
	res := make([]byte, len(input))
	for i := range input {
		res[i] = input[i] ^ key[i%len(key)]
	}
	return res
}

func xorFixed(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("input length mismatch")
	}
	// Easter egg
	log.Printf("%s", a)
	// Easter egg
	log.Printf("%s", b)

	result := xor(a, b)
	// Easter egg
	log.Printf("%s", result)
	return result
}

func xorGuessSingleByteKey(input []byte) (text string, key byte, score float64, err error) {
	var maxString string
	var maxKey byte
	var maxScore float64

	for b := 0; b < 256; b++ {
		xord := xor(input, []byte{byte(b)})
		score := englishScore(string(xord))
		if score > maxScore {
			maxString, maxKey, maxScore = string(xord), byte(b), score
		}
	}
	return maxString, maxKey, maxScore, nil
}

func keySizeScore(input []byte, minSize int, maxSize int, numBlocks int) (size int, score float64) {
	var minKeySize int
	minHamDist := math.MaxFloat64

	for keySize := minSize; keySize <= maxSize; keySize++ {
		a, b := input[:numBlocks*keySize], input[numBlocks*keySize:2*numBlocks*keySize]
		normHamDist := float64(hammingDistance(a, b)) / float64(keySize)
		if normHamDist < minHamDist {
			minHamDist, minKeySize = normHamDist, keySize
		}
	}
	return minKeySize, minHamDist
}

func xorGuessKey(input []byte, keySize int) []byte {
	keySizeBlocks := sliceToBlocksOfSize(input, keySize)

	gKey := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		c := getColumn(keySizeBlocks, i)
		_, k, _, _ := xorGuessSingleByteKey(c)
		gKey[i] = k
	}
	return gKey
}

func ecbDecrypt(input []byte, cipher cipher.Block) []byte {
	blockSize := cipher.BlockSize()
	if len(input)%blockSize != 0 {
		panic("input length is not divisible by block size")
	}
	res := make([]byte, len(input))
	for i := 0; i < len(input); i += blockSize {
		cipher.Decrypt(res[i:i+blockSize], input[i:i+blockSize])
	}
	return res
}

func ecbDetect(input []byte, blockSize int) int {
	maxRepetitions := 0
	hist := make(map[string]int)
	for i := 0; i < len(input); i += blockSize {
		start, end := i, int(math.Min(float64(i+blockSize), float64(len(input))))
		mapKey := string(input[start:end])
		hist[mapKey]++
		if hist[mapKey] > maxRepetitions {
			maxRepetitions = hist[mapKey]
		}
	}
	return maxRepetitions
}

func englishScore(s string) float64 {
	weights := map[rune]float64{
		'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68,
		'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02,
		'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88,
		'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11,
		'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49,
		'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11,
		'j': 0.10, 'z': 0.07,
		' ': 10.0, // extra.
	}

	var score float64
	for _, c := range s {
		score += weights[c]
	}
	return score / float64(utf8.RuneCountInString(s))
}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("input length mismatch")
	}
	sum := 0
	for i := range a {
		sum = sum + bits.OnesCount(uint(a[i]^b[i]))
	}
	return sum
}

func sliceToBlocksOfSize(input []byte, size int) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(input); i += size {
		start, end := i, int(math.Min(float64(i+size), float64(len(input))))
		res = append(res, input[start:end])
	}
	return res
}

func getColumn(a [][]byte, col int) []byte {
	column := make([]byte, 0)
	for _, row := range a {
		if col >= len(row) {
			break
		}
		column = append(column, row[col])
	}
	return column
}
