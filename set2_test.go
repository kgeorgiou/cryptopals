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

		unpadded, _ := pkcs7Unpad(padded)
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

func TestEcbOracleDetectBlockSize(t *testing.T) {
	testSize := 16
	oracle := newEcbOracle(testSize, false)
	size, _ := ecbOracleDetectBlockSize(oracle)
	if size != testSize {
		t.Fatalf("Actual: %d, Expected: %d", size, 16)
	}
}
func TestEcbOracleWithPrefixDetectBlockSize(t *testing.T) {
	testSize := 16
	oracle := newEcbOracle(testSize, true)
	size, _ := ecbOracleDetectBlockSize(oracle)
	if size != testSize {
		t.Fatalf("Actual: %d, Expected: %d", size, 16)
	}
}

func TestChallenge12(t *testing.T) {
	oracle := newEcbOracle(16, false)
	pt := ecbOraclePaddingAttack(oracle)
	t.Logf("Plaintext: %s", string(pt))
}

func TestChallenge13(t *testing.T) {
	userProfile := ecbCutAndPaste()

	if !userProfile.IsAdmin() {
		t.Errorf("expected user profile to have admin previlleges")
	}
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

func TestFindPrefixSize(t *testing.T) {
	oracle := newEcbOracle(16, true)
	s := findPrefixSize(oracle, 16)
	t.Logf("s detected: %d", s)
}

func TestFindPrefixLengthModBlockSize(t *testing.T) {
	oracle := newEcbOracle(16, true)
	s := findPrefixLengthModBlockSize(oracle, 16)
	t.Logf("s detected: %d", s)
}

func TestChallenge14(t *testing.T) {
	oracle := newEcbOracle(16, true)
	pt := ecbOraclePaddingAttack(oracle)
	t.Logf("Plaintext: %s", string(pt))
}

func TestChallenge16(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	cipher, _ := aes.NewCipher(key)

	ciphertext := encryptUserData(cipher, iv, "AAAAAAAAAAAAAAAA")
	isAdmin, err := decryptUserData(cipher, iv, ciphertext)
	if err != nil {
		t.Errorf("failed to decrypt user data: %v", err)
	}
	if !isAdmin {
		t.Errorf("user is not admin")
	}
}
