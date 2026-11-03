package limits

import (
	"strings"
	"testing"
)

func TestReadAllRejectsLimitPlusOne(t *testing.T) {
	if _, err := ReadAll(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("oversized input accepted")
	}
}
