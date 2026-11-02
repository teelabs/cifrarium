package recovery

import "testing"

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
