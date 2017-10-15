package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"
)

func TestChallenge1(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{
			"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}

	for _, tt := range tests {
		actual := hexToBase64(tt.in)
		if actual != tt.out {
			t.Errorf("actual: %v :: expected: %v", actual, tt.out)
		}
	}
}

func TestChallenge2(t *testing.T) {
	tests := []struct {
		a   string
		b   string
		out string
	}{
		{
			"1c0111001f010100061a024b53535009181c",
			"686974207468652062756c6c277320657965",
			"746865206b696420646f6e277420706c6179",
		},
	}

	for _, tt := range tests {
		a, err := hex.DecodeString(tt.a)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}
		b, err := hex.DecodeString(tt.b)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}

		actual := xorFixed(a, b)
		expected, err := hex.DecodeString(tt.out)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}

		if !bytes.Equal(actual, expected) {
			t.Errorf("actual: %s :: expected: %v", actual, expected)
		}
	}
}

func TestChallenge3(t *testing.T) {
	tests := []struct {
		input string
	}{
		{
			"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
		},
	}

	for _, tt := range tests {
		input, err := hex.DecodeString(tt.input)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}
		plaintext, key, _, err := xorGuessSingleByteKey(input)
		if err != nil {
			t.Fatalf("xorGuessSingleByteKey returned error: %v", err)
		}

		t.Logf("plaintext: %s :: key: %d", plaintext, key)
	}
}

func TestChallenge4(t *testing.T) {
	inFile, _ := os.Open("4.txt")
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	var maxPlaintext, maxCiphertext string
	var maxScore float64
	var maxKey byte
	for scanner.Scan() {
		hexInput := scanner.Text()
		input, err := hex.DecodeString(hexInput)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}
		plaintext, key, score, _ := xorGuessSingleByteKey(input)
		if score > maxScore {
			maxPlaintext, maxKey, maxScore, maxCiphertext = plaintext, key, score, hexInput
		}
	}

	t.Logf("ciphertext %s :: plaintext: %s :: key %d", maxCiphertext, maxPlaintext, maxKey)
}

func TestChallenge5(t *testing.T) {
	tests := []struct {
		plaintext  string
		key        string
		ciphertext string
	}{
		{
			"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
			"ICE",
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}
	for _, tt := range tests {
		output := xor([]byte(tt.plaintext), []byte(tt.key))
		hexOutput := hex.EncodeToString(output)
		if hexOutput != tt.ciphertext {
			t.Errorf("actual: %s :: expected: %s.", hexOutput, tt.ciphertext)
		}
	}
}

func TestChallenge6(t *testing.T) {
	content, err := ioutil.ReadFile("6.txt")
	if err != nil {
		t.Fatal("can't read file contents")
	}
	decoded := make([]byte, len(content))
	base64.StdEncoding.Decode(decoded, content)

	keySize, score := keySizeScore(decoded, 2, 50, 4)
	t.Logf("key size: %d :: score: %.2f", keySize, score)

	key := xorGuessKey(decoded, keySize)
	t.Logf("guessed key: %s", key)

	plaintext := xor(decoded, key)
	t.Logf("plaintext: %s", plaintext)
}

func TestChallenge7(t *testing.T) {
	content, err := ioutil.ReadFile("7.txt")
	if err != nil {
		t.Fatal("can't read file contents")
	}
	decoded := make([]byte, len(content))
	base64.StdEncoding.Decode(decoded, content)

	key := []byte("YELLOW SUBMARINE")
	cipher, _ := aes.NewCipher(key)
	plaintext := ecbDecrypt(decoded, cipher)
	if err != nil {
		t.Errorf("cannot decrypt file contents: %v", err)
	}

	t.Logf("plaintext: %s", plaintext)
}

func TestChallenge8(t *testing.T) {
	inFile, _ := os.Open("8.txt")
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	maxReps := 0
	var maxText string

	for scanner.Scan() {
		hexInput := scanner.Text()
		input, err := hex.DecodeString(hexInput)
		if err != nil {
			t.Fatalf("hex.DecodeString returned error: %v", err)
		}
		if reps := ecbDetect(input, 16); reps > maxReps {
			maxReps = reps
			maxText = hexInput
		}
	}

	t.Logf("ciphertext most likely to be encrypted in AES ECB mode: %s :: block repetitions: %d", maxText, maxReps)
}

func TestHammingDistance(t *testing.T) {
	tests := []struct {
		a   []byte
		b   []byte
		out int
	}{
		{
			[]byte("this is a test"),
			[]byte("wokka wokka!!!"),
			37,
		},
		{
			[]byte{8}, // 1 0 0 0
			[]byte{9}, // 1 0 0 1
			1,
		},
		{
			[]byte{8}, // 1 0 0 0
			[]byte{7}, // 0 1 1 1
			4,
		},
		{
			[]byte{255}, // 1 1 1 1 1 1 1 1
			[]byte{0},   // 0 0 0 0 0 0 0 0
			8,
		},
		{
			[]byte{0},  // 0 0 0 0 0
			[]byte{16}, // 1 0 0 0 0
			1,
		},
	}
	for _, tt := range tests {
		res := hammingDistance(tt.a, tt.b)
		if res != tt.out {
			t.Errorf("actual %d :: expected %d", res, tt.out)
		}
	}
}

func TestKeySizeScore(t *testing.T) {
	tests := []struct {
		input     []byte
		minSize   int
		maxSize   int
		numBlocks int
		keySize   int
		score     float64
	}{
		{
			[]byte("abcdabcd"),
			2,
			4,
			1,
			4,
			0.0,
		},
	}
	for _, tt := range tests {
		size, score := keySizeScore(tt.input, tt.minSize, tt.maxSize, tt.numBlocks)

		if size != tt.keySize {
			t.Errorf("actual: %d :: expected: %d", size, tt.keySize)
		}

		if score != tt.score {
			t.Errorf("actual: %f :: expected: %f", score, tt.score)
		}
	}
}
