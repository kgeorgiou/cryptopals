package cryptopals

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

var big1 = big.NewInt(1)
var big2 = big.NewInt(2)
var big3 = big.NewInt(3)

type dhParams struct {
	p, g *big.Int
}
type dhKeypair struct {
	PublicKey, PrivateKey *big.Int
}

func (mine *dhKeypair) deriveSecret(theirs *dhKeypair, params *dhParams) []byte {
	return new(big.Int).Exp(theirs.PublicKey, mine.PrivateKey, params.p).Bytes()
}

func dhGenerate(params *dhParams) *dhKeypair {
	prv, _ := rand.Int(rand.Reader, params.p)
	pub := new(big.Int).Exp(params.g, prv, params.p)
	return &dhKeypair{PublicKey: pub, PrivateKey: prv}
}

func rsaGenerate() *rsa.PrivateKey {
	prvKey := &rsa.PrivateKey{}

	for {
		p, _ := rand.Prime(rand.Reader, 1024)
		q, _ := rand.Prime(rand.Reader, 1024)

		pMinusOne := new(big.Int).Sub(p, big1)
		qMinusOne := new(big.Int).Sub(q, big1)
		et := new(big.Int).Mul(pMinusOne, qMinusOne)

		prvKey.Primes = []*big.Int{p, q}
		prvKey.E = 3
		prvKey.N = new(big.Int).Mul(p, q)
		prvKey.D = new(big.Int).ModInverse(big3, et)

		// (p-1)*(q-1) is not a relative prime with E, D will be nil
		// if D is 1, our ciphertext will be the same as the plaintext
		if prvKey.D != nil && prvKey.D.Cmp(big1) > 0 {
			break
		}
	}

	return prvKey
}

func rsaEncrypt(m []byte, key *rsa.PublicKey) []byte {
	mInt := new(big.Int).SetBytes(m)
	if mInt.Cmp(key.N) >= 0 {
		panic("m is bigger than N")
	}
	return mInt.Exp(mInt, big.NewInt(int64(key.E)), key.N).Bytes()
}

func rsaDecrypt(m []byte, key *rsa.PrivateKey) []byte {
	mInt := new(big.Int).SetBytes(m)
	if mInt.Cmp(key.N) >= 0 {
		panic("m is bigger than N")
	}
	return mInt.Exp(mInt, key.D, key.N).Bytes()
}
