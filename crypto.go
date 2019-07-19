package e3dbClients

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/google/uuid"
	sodium "golang.org/x/crypto/nacl/sign"
)

const (
	// https://security.stackexchange.com/questions/50878/ecdsa-vs-ecdh-vs-ed25519-vs-curve25519
	DefaultEncryptionKeyType = "curve25519"
	DefaultSigningKeyType    = "ed25519"
)

// ToznyAuthenticatedContext represents the contextual information provided by cyclops to downstream services
// when a user is successfully authenticated.
type ToznyAuthenticatedContext struct {
	ClientID       uuid.UUID            `json:"client_id"`
	AccountID      uuid.UUID            `json:"account_id"`
	Name           string               `json:"name"`
	EncryptionKeys PublicEncryptionKeys `json:"encryption_keys"`        // Tozny does not know a user's private encryption key
	SignatureKeys  PublicSignatureKeys  `json:"signing_keys,omitempty"` // Tozny does not know a user's private signing key
	ClientType     string               `json:"type"`
}

// Key wraps material generated using an algorithm/curve for use in cryptographic operations
type Key struct {
	Material string
	Type     string // e.g. Curve25519
}

// Keys is a map of key type to key material
type Keys map[string]string

// AsymmetricKeypair wraps a public and private key used for
// asymmetric cryptographic operations.
type AsymmetricKeypair struct {
	Private Key // Used for decryption and signing
	Public  Key // Used for authentication and encryption
}

// SigningKeys wraps a keypair for signing and authenticating requests
type SigningKeys AsymmetricKeypair

// EncryptionKeys wraps a keypair for encrypting and decrypting data
type EncryptionKeys AsymmetricKeypair

// PublicEncryptionKeys are a set of keys, NIST or Sodium, used within TozStore to encrypt stored data.
// It's the responsibility of the user to assign proper key types to raw keys obtained internally (db)
// or externally (client calls).
type PublicEncryptionKeys Keys

// PublicSignatureKeys are a set of key, NIST or Sodium, used within Tozny to sign requests
// It's the responsibility of the user to assign proper key types to raw keys obtained internally (db)
// or externally (client calls).
type PublicSignatureKeys Keys

// GenerateSigningKeys generates a `base64.RawURLEncoding` private and public key
// for signing requests and data on behalf of Tozny clients,
// returning the signing keys and error (if any).
func GenerateSigningKeys() (SigningKeys, error) {
	var signingKeys SigningKeys
	signingKeyBytes, privateSigningKeyBytes, err := sodium.GenerateKey(rand.Reader)
	if err != nil {
		return signingKeys, err
	}
	signingKey := base64.RawURLEncoding.EncodeToString(signingKeyBytes[:])
	privateSigningKey := base64.RawURLEncoding.EncodeToString(privateSigningKeyBytes[:])
	signingKeys = SigningKeys{
		Private: Key{
			Material: privateSigningKey,
			Type:     DefaultSigningKeyType},
		Public: Key{
			Material: signingKey,
			Type:     DefaultSigningKeyType},
	}
	return signingKeys, err
}
