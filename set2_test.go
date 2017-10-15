package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestChallenge9(t *testing.T) {
	tests := []struct {
		in        []byte
		blockSize int
		out       []byte
	}{
		{
			[]byte("YELLOW SUBMARINE"),
			20,
			[]byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		},
		{
			[]byte("12345678"),
			8,
			[]byte("12345678\x08\x08\x08\x08\x08\x08\x08\x08"),
		},
	}
	for _, tt := range tests {
		padded := pkcs7Pad(tt.in, tt.blockSize)
		if !bytes.Equal(padded, tt.out) {
			t.Errorf("Actual %v :: Expected %v", padded, tt.out)
		}

		unpadded := pkcs7Unpad(padded)
		if !bytes.Equal(unpadded, tt.in) {
			t.Errorf("Actual %v :: Expected %v", unpadded, tt.in)
		}
	}
}

func TestChallenge10(t *testing.T) {
	content, err := ioutil.ReadFile("10.txt")
	if err != nil {
		t.Fatal("Can't read file contents")
	}
	decoded := make([]byte, len(content))
	base64.StdEncoding.Decode(decoded, content)

	key := []byte("YELLOW SUBMARINE")
	iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	cipher, _ := aes.NewCipher(key)
	plaintext := cbcDecrypt(decoded, iv, cipher)
	t.Logf("%s", plaintext)

	ciphertext := cbcEncrypt(plaintext, iv, cipher)
	if !bytes.Equal(decoded, ciphertext) {
		t.Errorf("Expected encrypted plaintext to match original ciphertext")
	}
}

func TestChallenge11(t *testing.T) {
	// 64*a
	msg := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ciphertext := encryptionOracle(msg)
	ciphertextHex := hex.EncodeToString(ciphertext)

	t.Logf("Ciphertext: %s", ciphertextHex)
	if bytes.Equal(ciphertext[16:32], ciphertext[32:48]) {
		t.Logf("Mode Used: ECB")
	} else {
		t.Logf("Mode Used: CBC")
	}
}

func TestChallenge12(t *testing.T) {
	size, _ := ecbOracleDetectBlockSize(ecbOracle)
	if size != 16 {
		t.Logf("Actual: %d, Expected: %d", size, 16)
	}
}

func TestChallenge13(t *testing.T) {
	userProfile := ecbCutAndPaste()

	if !userProfile.IsAdmin() {
		t.Errorf("expected user profile to have admin previlleges")
	}
}

func TestChallenge15(t *testing.T) {
	pt := ecbOraclePaddingAttack(ecbOracle)
	t.Logf("Plaintext: %s", string(pt))
}

func TestProfileFor(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{
			"foo@bar.com",
			"email=foo@bar.com&uid=10&role=user",
		},
		{
			"foo@bar.com&role=admin",
			"email=foo@bar.com_role_admin&uid=10&role=user",
		},
	}
	for _, tt := range tests {
		out := profileFor(tt.in)
		if out != tt.out {
			t.Errorf("actual %s :: expected %s", out, tt.out)
		}
	}
}
