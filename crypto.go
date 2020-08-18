package e3dbClients

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// https://security.stackexchange.com/questions/50878/ecdsa-vs-ecdh-vs-ed25519-vs-curve25519
	DefaultEncryptionKeyType = "curve25519"
	DefaultSigningKeyType    = "ed25519"
	SymmetricKeySize         = 32
	NonceSize                = 24
	SaltSize                 = 16
	AccountDerivationRounds  = 1000
)

// SymmetricKey is used for fast encryption of larger amounts of data
// also referred to as the 'SecretKey'
type SymmetricKey *[SymmetricKeySize]byte

// Nonce is a type that represents nonce randomly generated unique value that is used once in encrypting data.
type Nonce *[NonceSize]byte

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

// PublicSigningKeys are a set of key, NIST or Sodium, used within Tozny to sign requests
// It's the responsibility of the user to assign proper key types to raw keys obtained internally (db)
// or externally (client calls).
type PublicSigningKeys Keys

// GenerateSigningKeys generates a `base64.RawURLEncoding` private and public key
// for signing requests and data on behalf of Tozny clients,
// returning the signing keys and error (if any).
func GenerateSigningKeys() (SigningKeys, error) {
	var signingKeys SigningKeys
	signingKeyBytes, privateSigningKeyBytes, err := sign.GenerateKey(rand.Reader)
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

// GenerateKeyPair creates a new Curve25519 keypair for cryptographic operations.
func GenerateKeyPair() (EncryptionKeys, error) {
	var encryptionKeys EncryptionKeys
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return encryptionKeys, err
	}

	publicKey := Base64Encode(pub[:])
	privateKey := Base64Encode(priv[:])
	encryptionKeys = EncryptionKeys{
		Private: Key{
			Material: privateKey,
			Type:     DefaultEncryptionKeyType,
		},
		Public: Key{
			Material: publicKey,
			Type:     DefaultEncryptionKeyType,
		},
	}

	return encryptionKeys, err
}

// EncryptData encrypts a collection of data of string key and values using
// Tozny v1 Record encryption, returning the encrypted data.
func EncryptData(Data map[string]string, ak SymmetricKey) *map[string]string {
	encryptedData := make(map[string]string)
	for k, v := range Data {
		dk := RandomSymmetricKey()
		ef, efN := SecretBoxEncryptToBase64([]byte(v), dk)
		edk, edkN := SecretBoxEncryptToBase64(dk[:], ak)
		encryptedData[k] = fmt.Sprintf("%s.%s.%s.%s", edk, edkN, ef, efN)
	}
	return &encryptedData
}

// DecryptData decrypts a collection of data of string key and values encrypted using Tozny v1 Record encryption,
// returning the decrypted data and error (if any).
func DecryptData(Data map[string]string, ak SymmetricKey) (*map[string]string, error) {
	decryptedData := make(map[string]string)
	for k, v := range Data {
		fields := strings.SplitN(v, ".", 4)
		if len(fields) != 4 {
			return &decryptedData, errors.New("invalid record data format")
		}

		edk := fields[0]
		edkN := fields[1]
		ef := fields[2]
		efN := fields[3]

		dkBytes, err := SecretBoxDecryptFromBase64(edk, edkN, ak)
		if err != nil {
			return &decryptedData, err
		}

		dk := MakeSymmetricKey(dkBytes)
		field, err := SecretBoxDecryptFromBase64(ef, efN, dk)
		if err != nil {
			return &decryptedData, errors.New("decryption of field data failed")
		}

		decryptedData[k] = string(field)
	}

	return &decryptedData, nil
}

// EncryptAccessKey returns encrypted access key with nonce attached.
func EncryptAccessKey(rawAK SymmetricKey, encryptionKeys EncryptionKeys) (string, error) {
	eak, eakN, err := BoxEncryptToBase64(rawAK[:], encryptionKeys)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", eak, eakN), err
}

// RandomSymmetricKey generates a random symmetric key (secret).
func RandomSymmetricKey() SymmetricKey {
	key := [SymmetricKeySize]byte{}
	_, err := rand.Read(key[:])
	if err != nil {
		// we don't expect this to fail
		panic("random number generation failed")
	}
	return &key
}

// RandomNonce generates a random nonce of size NoneSize
func RandomNonce() Nonce {
	b := [NonceSize]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		// we don't expect this to fail
		panic("random number generation failed")
	}
	return &b
}

// GenerateRandomBytes generate a random number of bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// GenerateRandomString generate a random base64 encoded string of n bytes.
func GenerateRandomString(n int) (string, error) {
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return Base64Encode(bytes), err
}

// BoxEncryptToBase64 uses asymmetric encryption keys to encrypt data
func BoxEncryptToBase64(data []byte, encryptionKeys EncryptionKeys) (string, string, error) {
	n := RandomNonce()
	rawPubKey, err := Base64Decode(encryptionKeys.Public.Material)
	if err != nil {
		return "", "", err
	}
	rawPrivKey, err := Base64Decode(encryptionKeys.Private.Material)
	if err != nil {
		return "", "", err
	}
	pubKey := MakeSymmetricKey(rawPubKey)
	privKey := MakeSymmetricKey(rawPrivKey)
	ciphertext := box.Seal(nil, data, n, pubKey, privKey)
	return Base64Encode(ciphertext), Base64Encode(n[:]), err
}

func BoxDecryptFromBase64(ciphertext, nonce string, pubKey SymmetricKey, privKey SymmetricKey) ([]byte, error) {
	ciphertextBytes, err := Base64Decode(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := Base64Decode(nonce)
	if err != nil {
		return nil, err
	}

	n := MakeNonce(nonceBytes)
	plaintext, ok := box.Open(nil, ciphertextBytes, n, pubKey, privKey)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// SecretBoxEncryptToBase64 uses an NaCl secret_box to encrypt a byte
// slice with the given secret key and a random nonce,
// returning the Base64URL encoded ciphertext and nonce.
func SecretBoxEncryptToBase64(data []byte, key SymmetricKey) (string, string) {
	n := RandomNonce()
	box := secretbox.Seal(nil, data, n, key)
	return Base64Encode(box), Base64Encode(n[:])
}

// SecretBoxDecryptFromBase64 uses NaCl secret_box to decrypt a
// string containing ciphertext along with the associated
// nonce, both Base64URL encoded. Returns the ciphertext bytes,
// or an error if the authentication check fails when decrypting.
func SecretBoxDecryptFromBase64(ciphertext, nonce string, key SymmetricKey) ([]byte, error) {
	ciphertextBytes, err := Base64Decode(ciphertext)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := Base64Decode(nonce)
	if err != nil {
		return nil, err
	}

	n := MakeNonce(nonceBytes)
	plaintext, ok := secretbox.Open(nil, ciphertextBytes, n, key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// MakeSymmetricKey loads an existing secret key from a byte array.
func MakeSymmetricKey(b []byte) SymmetricKey {
	key := [SymmetricKeySize]byte{}
	copy(key[:], b)
	return &key
}

// MakeNonce loads an existing nonce from a byte array.
func MakeNonce(b []byte) Nonce {
	n := [NonceSize]byte{}
	copy(n[:], b)
	return &n
}

// Base64Encode wrapper to base64 encode data.
func Base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64Decode wrapper to base64 decode data.
func Base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// DecodeSymmetricKey decodes a public key from a Base64URL encoded
// string containing a 256-bit Curve25519 public key, returning an
// error if the decode operation fails.
func DecodeSymmetricKey(s string) (SymmetricKey, error) {
	bytes, err := Base64Decode(s)
	if err != nil {
		return nil, err
	}
	return MakeSymmetricKey(bytes), nil
}

// DecryptEAK decodes and decrypts a raw encrypted access key
// returning the decrypted symmetric key and error (if any).
func DecryptEAK(eak string, authorizerPublicKey string, privateKey SymmetricKey) (SymmetricKey, error) {
	fields := strings.SplitN(eak, ".", 2)
	if len(fields) != 2 {
		return nil, errors.New(fmt.Sprintf("invalid access key format: %s", eak))
	}

	decodedAuthorizerPublicKey, err := DecodeSymmetricKey(authorizerPublicKey)
	if err != nil {
		return nil, err
	}

	akBytes, err := BoxDecryptFromBase64(fields[0], fields[1], decodedAuthorizerPublicKey, privateKey)
	if err != nil {
		return nil, errors.New("access key decryption failure")
	}

	ak := MakeSymmetricKey(akBytes)
	return ak, nil
}

// Encrypt uses an NaCl secret_box to encrypt a byte
// slice with the given secret key and a random nonce,
// returning the Base64 encoded ciphertext and nonce.
func Encrypt(data []byte, key SymmetricKey) string {
	nonce := RandomNonce()
	message := secretbox.Seal(nil, data, nonce, key)
	return base64.RawURLEncoding.EncodeToString(nonce[:]) + ":" + base64.RawURLEncoding.EncodeToString(message)
}

// Decrypt uses NaCl secret_box to decrypt a
// string containing ciphertext along with the associated
// nonce, both Base64 encoded. Returns the ciphertext bytes,
// or an error if the authentication check fails when decrypting.
func Decrypt(ciphertext string, key SymmetricKey) ([]byte, error) {
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Expected two parts in cipher text %q", ciphertext)
	}
	//decode the nonce and message
	nonceBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	nonce := MakeNonce(nonceBytes)
	message, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	plaintext, ok := secretbox.Open(nil, message, nonce, key)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// Sign does a detached signature of the requested message using the provided key
func Sign(message []byte, key *[64]byte) []byte {
	bytes := sign.Sign(nil, message, key)
	offset := len(bytes) - len(message)
	return bytes[:offset]
}

// DeriveSymmetricKey create a symmetric encryption key from a seed and a salt
func DeriveSymmetricKey(seed []byte, salt []byte, iter int) *[32]byte {
	secretKey := new([32]byte)
	skBytes := pbkdf2.Key(seed, salt, iter, 32, sha512.New)
	copy(secretKey[:], skBytes)
	return secretKey
}

// DeriveCryptoKey creates an encryption key pair from a seed and a salt
func DeriveCryptoKey(seed []byte, salt []byte, iter int) (*[32]byte, *[32]byte) {
	// Make the private public keys
	publicKey := new([32]byte)
	privateKey := new([32]byte)
	// Seed the key using pbkdf2
	seed25519 := pbkdf2.Key(seed, salt, iter, 32, sha512.New)
	// Libsodium hashes the seed with sha512 for the secret key
	hasher := sha512.New()
	hasher.Write(seed25519)
	sk := hasher.Sum(nil)
	copy(privateKey[:], sk)
	// Make the key pair
	curve25519.ScalarBaseMult(publicKey, privateKey)
	return publicKey, privateKey
}

// DeriveSigningKey creates an encryption key pair from a seed and a salt
func DeriveSigningKey(seed []byte, salt []byte, iter int) (*[32]byte, *[64]byte) {
	// Make the private public keys
	publicKey := new([32]byte)
	privateKey := new([64]byte)
	// Seed the key using pbkdf2
	seed25519 := pbkdf2.Key(seed, salt, iter, 32, sha512.New)
	// Create the signing key pair
	privateKeyBytes := ed25519.NewKeyFromSeed(seed25519)
	copy((*privateKey)[:], privateKeyBytes[:])
	copy((*publicKey)[:], privateKeyBytes[32:])
	return publicKey, privateKey
}
