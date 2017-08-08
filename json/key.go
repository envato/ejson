package json

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	// PublicKeyField is the key name at which the public key should be
	// stored in an EJSON document.
	PublicKeyField = "_public_key"

	// PrivateKeyEncField key name at which the KMS encrypted private key should be stored in
	// the EJSON document.
	PrivateKeyEncField = "_private_key_enc"
)

// ErrPublicKeyMissing indicates that the PublicKeyField key was not found
// at the top level of the JSON document provided.
var ErrPublicKeyMissing = errors.New("public key not present in EJSON file")

// ErrPublicKeyInvalid means that the PublicKeyField key was found, but the
// value could not be parsed into a valid key.
var ErrPublicKeyInvalid = errors.New("public key has invalid format")

// ExtractMetadata finds the _public_key value in an EJSON document and
// parses it into a key usable with the crypto library.
func ExtractMetadata(data []byte) (key [32]byte, privKeyEnc string, err error) {
	var (
		obj map[string]interface{}
		ks  string
		ok  bool
		bs  []byte
	)
	err = json.Unmarshal(data, &obj)
	if err != nil {
		return
	}
	// optional fields
	pkEnc, ok := obj[PrivateKeyEncField]
	if ok {
		privKeyEnc = pkEnc.(string)
	}

	// requied
	k, ok := obj[PublicKeyField]
	if !ok {
		goto missing
	}
	ks, ok = k.(string)
	if !ok {
		goto invalid
	}
	if len(ks) != 64 {
		goto invalid
	}
	bs, err = hex.DecodeString(ks)
	if err != nil {
		goto invalid
	}
	if len(bs) != 32 {
		goto invalid
	}
	copy(key[:], bs)
	return
missing:
	err = ErrPublicKeyMissing
	return
invalid:
	err = ErrPublicKeyInvalid
	return
}
