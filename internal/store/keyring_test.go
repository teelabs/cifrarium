package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/teelabs/cifrarium/internal/recovery"
)

func TestRecoverySharesRestoreBothKeyringSecrets(t *testing.T) {
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := RecoveryShares(op, signing)
	if err != nil {
		t.Fatal(err)
	}
	for i, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		gotOp, gotSigning, err := RecoverKeys([]recovery.Share{shares[pair[0]], shares[pair[1]]})
		if err != nil || string(gotOp) != string(op) || string(gotSigning) != string(signing) {
			t.Fatalf("pair %d: %v", i, err)
		}
	}
}
