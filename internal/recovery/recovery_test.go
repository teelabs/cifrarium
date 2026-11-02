package recovery

import (
	"encoding/base64"
	"testing"
)

func TestAllPairs(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	shares, err := Split(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			got, err := Combine([]Share{shares[i], shares[j]})
			if err != nil || string(got) != string(key) {
				t.Fatalf("pair %d/%d: %v", i, j, err)
			}
		}
	}
	if _, err := Combine([]Share{shares[0]}); err == nil {
		t.Fatal("one share accepted")
	}
}
func TestRejectsDuplicateShareIndex(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	shares, err := Split(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawStdEncoding.DecodeString(shares[0].Value)
	raw[len(raw)-1] ^= 1
	shares[1].Value = base64.RawStdEncoding.EncodeToString(raw)
	if _, err := Combine([]Share{shares[0], shares[1]}); err == nil {
		t.Fatal("duplicate index accepted")
	}
}
