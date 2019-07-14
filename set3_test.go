package cryptopals

import "testing"

func TestChallenge17(t *testing.T) {
	for i := 0; i < 10; i++ {
		ans := attackCBCPaddingOracle()
		t.Log(string(ans))
	}
}
