package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	crypt "github.com/teelabs/cifrarium/internal/crypto"
	"github.com/teelabs/cifrarium/internal/limits"
)

const historySelectionVersion = 1

var ErrInvalidHistorySelection = errors.New("canonical backup history selection is invalid")

// HistorySelection identifies the operator-approved tip of a verified remote
// snapshot chain. The serialized value is encrypted; its signature authenticates
// the choice with the vault signing key.
type HistorySelection struct {
	Version   int    `json:"version"`
	Head      string `json:"head"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

type historySelectionPayload struct {
	Version int    `json:"version"`
	Head    string `json:"head"`
	Signer  string `json:"signer"`
}

func SealHistorySelection(head string, operational []byte, signing ed25519.PrivateKey) ([]byte, error) {
	if !validHistorySnapshotID(head) || len(operational) != 32 || len(signing) != ed25519.PrivateKeySize {
		return nil, ErrInvalidHistorySelection
	}
	selection := HistorySelection{
		Version: historySelectionVersion,
		Head:    head,
		Signer:  historySelectionSigner(signing.Public().(ed25519.PublicKey)),
	}
	payload, err := json.Marshal(historySelectionPayload{Version: selection.Version, Head: selection.Head, Signer: selection.Signer})
	if err != nil {
		return nil, ErrInvalidHistorySelection
	}
	selection.Signature = hex.EncodeToString(ed25519.Sign(signing, payload))
	plain, err := json.Marshal(selection)
	if err != nil {
		return nil, ErrInvalidHistorySelection
	}
	if err := limits.CheckBytes(len(plain), limits.MaxManifestBytes); err != nil {
		return nil, err
	}
	return crypt.Seal(plain, operational)
}

func OpenHistorySelection(raw, operational []byte, public ed25519.PublicKey) (HistorySelection, error) {
	if len(public) != ed25519.PublicKeySize || len(operational) != 32 || limits.CheckBytes(len(raw), limits.MaxManifestBytes) != nil {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	plain, err := crypt.Open(raw, operational)
	if err != nil || limits.CheckBytes(len(plain), limits.MaxManifestBytes) != nil {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	var selection HistorySelection
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selection); err != nil {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	canonical, err := json.Marshal(selection)
	if err != nil || !bytes.Equal(canonical, plain) {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	if selection.Version != historySelectionVersion || !validHistorySnapshotID(selection.Head) || selection.Signer != historySelectionSigner(public) {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	payload, err := json.Marshal(historySelectionPayload{Version: selection.Version, Head: selection.Head, Signer: selection.Signer})
	if err != nil {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	signature, err := hex.DecodeString(selection.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, payload, signature) {
		return HistorySelection{}, ErrInvalidHistorySelection
	}
	return selection, nil
}

func historySelectionSigner(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return hex.EncodeToString(sum[:])
}
