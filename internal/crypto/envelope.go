package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Envelope struct {
	Version    int    `json:"v"`
	WrappedKey string `json:"k"`
	Ciphertext string `json:"c"`
}

func Seal(plaintext, operationalKey []byte) ([]byte, error) {
	if len(operationalKey) != 32 {
		return nil, fmt.Errorf("operational key must be 32 bytes")
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, err
	}
	wrapped, err := sealWithKey(dataKey, operationalKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := sealWithKey(plaintext, dataKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Version: 1, WrappedKey: wrapped, Ciphertext: ciphertext})
}

func Open(raw, operationalKey []byte) ([]byte, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if e.Version != 1 {
		return nil, fmt.Errorf("unsupported envelope version")
	}
	dataKey, err := openWithKey(e.WrappedKey, operationalKey)
	if err != nil {
		return nil, err
	}
	return openWithKey(e.Ciphertext, dataKey)
}

func sealWithKey(plain, key []byte) (string, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	n := make([]byte, g.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return "", err
	}
	raw := append(n, g.Seal(nil, n, plain, nil)...)
	return base64.RawStdEncoding.EncodeToString(raw), nil
}
func openWithKey(encoded string, key []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < g.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	return g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], nil)
}

func Fingerprint(data []byte) string { h := sha256.Sum256(data); return fmt.Sprintf("%x", h[:]) }
