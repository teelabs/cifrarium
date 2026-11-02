package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/shamir"
)

type Share struct {
	Label       string `json:"label"`
	Value       string `json:"value"`
	Fingerprint string `json:"fingerprint"`
}

func Split(key []byte) ([]Share, error) {
	raw, err := shamir.Split(key, 3, 2)
	if err != nil {
		return nil, err
	}
	out := make([]Share, 3)
	for i, v := range raw {
		out[i] = Share{Label: fmt.Sprintf("cifrarium-%d", i+1), Value: base64.RawStdEncoding.EncodeToString(v), Fingerprint: fingerprint(v)}
	}
	return out, nil
}
func Combine(shares []Share) ([]byte, error) {
	if len(shares) != 2 {
		return nil, fmt.Errorf("exactly two shares are required")
	}
	seen := map[string]bool{}
	raw := make([]string, 2)
	for i, s := range shares {
		if s.Value == "" || seen[s.Value] {
			return nil, fmt.Errorf("duplicate or empty share")
		}
		seen[s.Value] = true
		raw[i] = s.Value
	}
	bytes := make([][]byte, 2)
	for i, v := range raw {
		b, err := base64.RawStdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("invalid share: %w", err)
		}
		bytes[i] = b
	}
	key, err := shamir.Combine(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func Verify(key []byte, shares []Share) bool {
	if len(key) == 0 {
		return false
	}
	recovered, err := Combine(shares)
	return err == nil && string(key) == string(recovered)
}
func fingerprint(v []byte) string {
	h := sha256.Sum256(v)
	return base64.RawStdEncoding.EncodeToString(h[:])
}
func NewKey() ([]byte, error) { b := make([]byte, 32); _, err := rand.Read(b); return b, err }
func ParseShare(s string) (Share, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return Share{}, fmt.Errorf("share must be label:value")
	}
	return Share{Label: parts[0], Value: parts[1]}, nil
}
