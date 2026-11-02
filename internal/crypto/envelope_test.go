package crypto

import "testing"

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	raw, err := Seal([]byte("secret"), key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(raw, key)
	if err != nil || string(got) != "secret" {
		t.Fatalf("open: %v %q", err, got)
	}
	key[0] = 1
	if _, err = Open(raw, key); err == nil {
		t.Fatal("tamper accepted")
	}
}
