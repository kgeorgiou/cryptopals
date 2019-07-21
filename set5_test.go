package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestChallenge33(t *testing.T) {
	p, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big2
	params := &dhParams{p, g}

	mine := dhGenerate(params)
	theirs := dhGenerate(params)

	mySecret := mine.deriveSecret(theirs, params)
	theirSecret := theirs.deriveSecret(mine, params)

	if !bytes.Equal(mySecret, theirSecret) {
		t.Errorf("expected %v to match %v", mySecret, theirSecret)
	}
}

func TestChallenge39(t *testing.T) {
	m := []byte("YELLOW SUBMARINE")

	key := rsaGenerate()
	ct := rsaEncrypt(m, &key.PublicKey)
	pt := rsaDecrypt(ct, key)

	if !bytes.Equal(m, pt) {
		t.Errorf("want %s, got %s", m, pt)
	}
}
