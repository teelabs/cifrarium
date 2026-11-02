package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/teelabs/cifrarium/internal/recovery"
	"github.com/zalando/go-keyring"
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

func TestLoadOrCreateDoesNotInitializeWhenKeyringIsUnavailable(t *testing.T) {
	want := errors.New("secret service unavailable")
	_, _, err := loadOrCreate("test",
		func(string, string) (string, error) { return "", want },
		func(string, string, string) error { t.Fatal("keyring was written after a backend failure"); return nil },
	)
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
}

func TestLoadOrCreateInitializesOnlyWhenSecretIsMissing(t *testing.T) {
	set := 0
	op, signing, err := loadOrCreate("test",
		func(string, string) (string, error) { return "", keyring.ErrNotFound },
		func(string, string, string) error { set++; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(op) != 32 || len(signing) != ed25519.PrivateKeySize || set != 1 {
		t.Fatalf("op=%d signing=%d writes=%d", len(op), len(signing), set)
	}
}

func TestValidateRecoveryVerifiesExistingVaultBeforeImport(t *testing.T) {
	root := t.TempDir()
	op := make([]byte, 32)
	if _, err := rand.Read(op); err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vault := New(root, op, signing)
	if _, err := vault.Save([]Record{{Path: "config", Data: []byte("safe"), Mode: 0600}}); err != nil {
		t.Fatal(err)
	}
	shares, err := RecoveryShares(op, signing)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecovery(root, []recovery.Share{shares[0], shares[1]}); err != nil {
		t.Fatalf("valid recovery rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "head.json"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecovery(root, []recovery.Share{shares[0], shares[1]}); err == nil {
		t.Fatal("tampered vault accepted for recovery import")
	}
}

func TestValidateRecoveryAllowsFreshVault(t *testing.T) {
	root := t.TempDir()
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
	if err := ValidateRecovery(root, []recovery.Share{shares[0], shares[1]}); err != nil {
		t.Fatalf("fresh vault rejected: %v", err)
	}
}
