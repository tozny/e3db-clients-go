package e3dbClients

import (
	"bufio"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tozny/e3db-clients-go/secretstream"
	"golang.org/x/crypto/blake2b"
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
	DefaultCryptographicMode = "Sodium"
	NISTCryptographicMode    = "NIST"
	SymmetricKeySize         = 32
	SigningKeySize           = 64
	PublicSigningKeySize     = 32
	NonceSize                = 24
	SaltSize                 = 16
	AccountDerivationRounds  = 1000
	IdentityDerivationRounds = 10000
	// The UUIDv5 is derived from a fixed namespace UUIDv4
	// "794253a4-310b-449d-9d8d-4575e8923f40" and a version string
	// "TFSP1;ED25519;BLAKE2B"
	ToznyFieldSignatureVersionV1 = "e7737e7c-1637-511e-8bab-93c4f3e26fd9" // UUIDv5 TFSP1;ED25519;BLAKE2B
	FILE_VERSION                 = 3
	FILE_BLOCK_SIZE              = 65536
	PublicSigningKeyLength       = 43
	PrivateSigningKeyLength      = 86
	PublicEncryptionKeyLength    = 43
	PrivateEncryptionKeyLength   = 43
)

var (
	PublicKeySizeError         = fmt.Errorf("the provided key was not %v bytes long", PublicSigningKeySize)
	SignatureVerificationError = fmt.Errorf("the provided message could not be verified with the provided key")
)

// SymmetricKey is used for fast encryption of larger amounts of data
// also referred to as the 'SecretKey'
type SymmetricKey *[SymmetricKeySize]byte

// SigningKey is used for fast signing and verifying properties of data
type SigningKey *[SigningKeySize]byte

// PublicSigningKey is used to verify a signatures
type PublicSigningKey = *[PublicSigningKeySize]byte

// PublicSigningKeyFromBytes returns a PublicSigningKey derived from a byte slice
func PublicSigningKeyFromBytes(publicSigningKeyBytes []byte) (PublicSigningKey, error) {
	if len(publicSigningKeyBytes) != PublicSigningKeySize {
		return nil, fmt.Errorf("PublicSigningKey must be %d bytes. Provided slice was %d bytes", PublicSigningKeySize, len(publicSigningKeyBytes))
	}
	var psk [PublicSigningKeySize]byte
	copy(psk[:], publicSigningKeyBytes)
	return &psk, nil
}

// PublicSigningKeyFromEncodedString returns a PublicSigningKey derived from a base64 encoded string
func PublicSigningKeyFromEncodedString(publicSigningKey string) (PublicSigningKey, error) {
	pskBytes, err := Base64Decode(publicSigningKey)
	if err != nil {
		return nil, err
	}
	return PublicSigningKeyFromBytes(pskBytes)
}

// Nonce is a type that represents nonce randomly generated unique value that is used once in encrypting data.
type Nonce *[NonceSize]byte

// Key wraps material generated using an algorithm/curve for use in cryptographic operations
type Key struct {
	Material string
	Type     string // e.g. Curve25519
}

// Keys is a map of key type to key material
type Keys map[string]string

// DecryptedData is a map of arbitrary key value pairs where value has been decrypted
type DecryptedData = map[string]string

// EncryptedData is a map of arbitrary key value pairs where the value is in an encrypted, "dotted quad" format
type EncryptedData = map[string]string

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
func EncryptData(data map[string]string, ak SymmetricKey) *EncryptedData {
	encryptedData := make(map[string]string)
	for k, v := range data {
		dk := RandomSymmetricKey()
		ef, efN := SecretBoxEncryptToBase64([]byte(v), dk)
		edk, edkN := SecretBoxEncryptToBase64(dk[:], ak)
		encryptedData[k] = fmt.Sprintf("%s.%s.%s.%s", edk, edkN, ef, efN)
	}
	return &encryptedData
}

// DecryptSignedData decrypts and verifies signed payloads for data that has been encrypted and signed using TFSP1;ED25519;BLAKE2B
func DecryptSignedData(data map[string]string, ak SymmetricKey, psk PublicSigningKey, salt string) (DecryptedData, error) {
	// the verify function uses the provided public signing key and salt to verify "key-message" pairs that are passed
	// as parameters, message should be a TFSP1;ED25519;BLAKE2B formatted string. The returned value is the unsigned message only.
	verify := func(key, message string) (string, error) {
		verifiedMessage, err := VerifyField(key, message, psk, salt)
		return verifiedMessage, err
	}
	return DecryptDataWithProcessFunction(data, ak, verify)
}

// DecryptData decrypts a collection of data of string key and values encrypted using Tozny v1 Record encryption,
// returning the decrypted data and error (if any).
func DecryptData(data map[string]string, ak SymmetricKey) (DecryptedData, error) {
	return DecryptDataWithProcessFunction(data, ak, func(key string, message string) (string, error) { return message, nil })
}

// DecryptDataWithProcessFunction decrypts a map of key value pairs where values are encrypted using Tozny v1 Record encryption
// after description a provided function is run against each key-value pair. The result of the function if err = nil is set as the value
func DecryptDataWithProcessFunction(data map[string]string, ak SymmetricKey, postprocess func(key string, value string) (string, error)) (DecryptedData, error) {
	decryptedData := make(map[string]string)
	for k, v := range data {
		fields := strings.SplitN(v, ".", 4)
		if len(fields) != 4 {
			return decryptedData, errors.New("invalid record data format")
		}

		edk := fields[0]
		edkN := fields[1]
		ef := fields[2]
		efN := fields[3]

		dkBytes, err := SecretBoxDecryptFromBase64(edk, edkN, ak)
		if err != nil {
			return decryptedData, err
		}

		dk := MakeSymmetricKey(dkBytes)
		field, err := SecretBoxDecryptFromBase64(ef, efN, dk)
		if err != nil {
			return decryptedData, errors.New("decryption of field data failed")
		}
		processedField, err := postprocess(k, string(field))
		if err != nil {
			return decryptedData, fmt.Errorf("decryption post processing failed: %w", err)
		}
		decryptedData[k] = processedField
	}

	return decryptedData, nil
}

// EncryptPrivateKey Encrypts a private key using a keypair.
func EncryptPrivateKey(privateKey Key, encryptionKeys EncryptionKeys) (string, error) {
	rawPrivateKeyBytes, err := Base64Decode(privateKey.Material)
	if err != nil {
		return "", err
	}
	eak, eakN, err := BoxEncryptToBase64(rawPrivateKeyBytes, encryptionKeys)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", eak, eakN), err
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
func Sign(message []byte, key SigningKey) []byte {
	bytes := sign.Sign(nil, message, key)
	offset := len(bytes) - len(message)
	return bytes[:offset]
}

// Verify a signature of message using the provided public key, for messages signed with TFSP1;ED25519;BLAKE2B
func Verify(signature string, message string, publicSigningKey PublicSigningKey) (string, error) {
	messageBytes, err := Base64Decode(message)
	if err != nil {
		return "", err
	}
	// This double encoding is required for TFSP1;ED25519;BLAKE2B signed messages,
	// as an artifact of the initial JS implementation
	doubleEncodedHash := []byte(Base64Encode(messageBytes))
	signatureBytes, err := Base64Decode(signature)
	if err != nil {
		return "", err
	}
	signedMessage := append(signatureBytes, doubleEncodedHash...)
	var psk [32]byte
	copy(psk[:], (*publicSigningKey)[:])
	outputBytes, verified := sign.Open(nil, signedMessage, &psk)
	if !verified {
		return "", SignatureVerificationError
	}
	return Base64Encode(outputBytes), nil
}

// SignField signs a field - a key value string pair - using Tozny Field Signing Version 1 (TFSV1) protocol
// https://github.com/tozny/internal-docs/blob/master/tozny-platform/notes/tozny-field-signing.md
// in a way compatible with the JS SDK implementation of TFSV1
// returning the signed string and error (if any)
func SignField(fieldName, fieldValue string, privateSigningKey SigningKey, salt string) (string, error) {
	// Construct the complete message to sign over
	message := salt + fieldName + fieldValue
	// Hash the message
	hashedMessage, err := HashString(message)
	if err != nil {
		return "", err
	}
	// Sign over the hashed message
	signatureBytes := Sign([]byte(hashedMessage), privateSigningKey)
	signature := Base64Encode(signatureBytes)
	// Construct the TFSV1 signature string
	signedFieldPrexixes := []string{ToznyFieldSignatureVersionV1, salt, fmt.Sprint(len(signature)), signature}
	signedFieldPrefix := strings.Join(signedFieldPrexixes, ";")

	return signedFieldPrefix + fieldValue, nil
}

// HashString returns a base64 encoded Blake2b hash of the provided message
func HashString(message string) (string, error) {
	hashedMessageAccumlator, err := blake2b.New(Blake2BBytes, nil)
	if err != nil {
		return "", err
	}
	hashedMessageAccumlator.Write([]byte(message))
	hashedMessageBytes := hashedMessageAccumlator.Sum(nil)
	hashedMessage := Base64Encode(hashedMessageBytes)
	return hashedMessage, nil
}

// VerifyField verifies TFSP1;ED25519;BLAKE2B fields using the provided public key and salt. Returning the unsigned message and error if any.
func VerifyField(fieldName, fieldValue string, publicSigningKey PublicSigningKey, salt string) (string, error) {
	parts := strings.SplitN(fieldValue, ";", 4)
	if parts[0] != ToznyFieldSignatureVersionV1 {
		return "", fmt.Errorf("VerifyField: The field signature version was not a known value and could not be verified. Provided version: %s", parts[0])
	}
	if len(parts) != 4 {
		return "", fmt.Errorf("VerfiyField: The field %s could not be verified. A known signature version was provided but signature was malformed", fieldName)
	}
	if salt != "" && salt != parts[1] {
		return "", fmt.Errorf("VerifyField: The field %s could not be verified. Invalid salt on signature", fieldName)
	}
	// Sum of the len of the first three parts plus the 3 semicolons removed in the split
	headerLength := len(parts[0]) + len(parts[1]) + len(parts[2]) + 3
	signatureLength, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", err
	}
	plainTextIndex := headerLength + signatureLength
	signature := fieldValue[headerLength:plainTextIndex]
	plaintext := fieldValue[plainTextIndex:]
	messageHash, err := HashString(parts[1] + fieldName + plaintext)
	if err != nil {
		return "", err
	}
	_, err = Verify(signature, messageHash, publicSigningKey)
	if err != nil {
		return "", err
	}
	return plaintext, nil
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

// DeriveIdentityCredentials derives a set of encryption keys, signing keys and a note name for the given parameters using pbkdf2
func DeriveIdentityCredentials(username string, password string, realmName string, nameSalt string) (string, EncryptionKeys, SigningKeys, error) {
	nameSeed := fmt.Sprintf("%s@realm:%s", username, realmName)
	if nameSalt != "" {
		nameSeed = fmt.Sprintf("%s:%s", nameSalt, nameSeed)
	}
	hashedMessageAccumlator, err := blake2b.New(Blake2BBytes, nil)
	if err != nil {
		return "", EncryptionKeys{}, SigningKeys{}, err
	}
	hashedMessageAccumlator.Write([]byte(nameSeed))
	hashedMessageBytes := hashedMessageAccumlator.Sum(nil)
	noteName := Base64Encode(hashedMessageBytes)
	cryptoPublicKey, cryptoPrivateKey := DeriveCryptoKey(
		[]byte(password),
		[]byte(nameSeed),
		IdentityDerivationRounds,
	)
	cryptoKeyPair := EncryptionKeys{
		Public: Key{
			Type:     DefaultEncryptionKeyType,
			Material: Base64Encode(cryptoPublicKey[:]),
		},
		Private: Key{
			Type:     DefaultEncryptionKeyType,
			Material: Base64Encode(cryptoPrivateKey[:]),
		},
	}
	signingPublicKey, signingPrivateKey := DeriveSigningKey(
		[]byte(password),
		[]byte(cryptoKeyPair.Public.Material+cryptoKeyPair.Private.Material),
		IdentityDerivationRounds,
	)
	signingKeyPair := SigningKeys{
		Public: Key{
			Type:     DefaultSigningKeyType,
			Material: Base64Encode(signingPublicKey[:]),
		},
		Private: Key{
			Type:     DefaultSigningKeyType,
			Material: Base64Encode(signingPrivateKey[:]),
		},
	}
	return noteName, cryptoKeyPair, signingKeyPair, nil
}

// EncryptFile encrypts the contents of the file plainFileName using the ak and stores the ciphertext in encryptedFileName
func EncryptFile(plainFileName string, encryptedFileName string, ak SymmetricKey) (int, string, error) {
	hasher := md5.New()
	var dk []byte
	dkSymmetric := RandomSymmetricKey()
	dk = dkSymmetric[:]
	edk, edkN := SecretBoxEncryptToBase64(dk[:], ak)
	headerText := fmt.Sprintf("%v.%s.%s.", FILE_VERSION, edk, edkN)
	headerBytes := []byte(headerText)
	hasher.Write(headerBytes)
	// create and open encryptedFileName
	tempFile, err := os.Create(encryptedFileName)
	if err != nil {
		return 0, "", err
	}
	// write the header to the encrypted file
	size, err := tempFile.Write(headerBytes)
	if err != nil {
		return 0, "", err
	}
	readFile, err := os.Open(plainFileName)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		if err = readFile.Close(); err != nil {
			fmt.Println("e3db-clients-go:EncryptFile: error closing file: ", err)
		}
	}()
	// create random header and write to encrypted file
	var header []byte
	nonce := RandomNonce()
	header = nonce[:]
	x, err := tempFile.Write(header)
	if err != nil {
		return 0, "", err
	}
	size += x
	hasher.Write(header)
	// create a new encryption stream
	encryptor, err := secretstream.NewEncryptor(header, dk)
	if err != nil {
		return 0, "", err
	}
	r := bufio.NewReader(readFile)
	var nextBlock []byte
	headBlock := make([]byte, FILE_BLOCK_SIZE)
	m, err := r.Read(headBlock)
	if err != nil {
		return 0, "", err
	}
	var block []byte
	// encrypt each block of the file with the appropriate tag
	for {
		nextBlock = make([]byte, FILE_BLOCK_SIZE)
		n, err := r.Read(nextBlock)
		var tag byte
		if err != nil {
			tag = secretstream.TagFinal
		} else {
			tag = secretstream.TagMessage
		}
		readBlock := headBlock[0:m]
		block, err = encryptor.Push(readBlock, nil, tag)
		if err != nil {
			return 0, "", err
		}
		y, err := tempFile.Write(block)
		if err != nil {
			return 0, "", err
		}
		size += y
		hasher.Write(block)
		if tag == secretstream.TagFinal {
			break
		}
		copy(headBlock, nextBlock)
		m = n
	}
	// calculate the checksum
	md5 := hasher.Sum(nil)
	checksum := base64.StdEncoding.EncodeToString(md5)
	return size, checksum, nil
}

// DecryptFile decrypts the contents of the file encryptedFileName using the ak and stores the plaintext in decryptedFileName
func DecryptFile(encryptedFileName string, decryptedFileName string, ak SymmetricKey) error {
	extraHeaderSize := secretstream.HeaderBytes
	blockSize := secretstream.AdditionalBytes + FILE_BLOCK_SIZE

	readFile, err := os.Open(encryptedFileName)
	if err != nil {
		return err
	}
	defer func() {
		if err = readFile.Close(); err != nil {
			fmt.Println("e3db-clients-go:DecryptFile: error closing file: ", err)
		}
	}()
	readFileHeader, err := os.Open(encryptedFileName)
	if err != nil {
		return err
	}
	defer func() {
		if err = readFileHeader.Close(); err != nil {
			fmt.Println("e3db-clients-go:DecryptFile: error closing header file: ", err)
		}
	}()

	decryptedFile, err := os.Create(decryptedFileName)
	if err != nil {
		return err
	}

	r := bufio.NewReader(readFileHeader)
	readFirst := make([]byte, 4096)

	n, err := r.Read(readFirst)
	if err != nil {
		return err
	}
	// read header and extract version, edk, edkN
	readHeaderBlock := readFirst[0:n]
	headerString := string(readHeaderBlock)
	s := strings.Split(headerString, ".")
	version, err := strconv.Atoi(s[0])
	if err != nil || version != FILE_VERSION {
		return err
	}
	edk := s[1]
	edkN := s[2]
	// get the dk
	dkBytes, err := SecretBoxDecryptFromBase64(edk, edkN, ak)
	if err != nil {
		return err
	}
	var dk []byte
	dkSymm := MakeSymmetricKey(dkBytes)
	dk = dkSymm[:]
	headerLength := len(s[0]+s[1]+s[2]) + 3
	readHeader := make([]byte, headerLength)
	readExtraHeader := make([]byte, extraHeaderSize)
	readCtxt := make([]byte, blockSize)

	_, err = readFile.Read(readHeader)
	if err != nil {
		return err
	}
	// get the extra header and use it to make decryption stream
	n, err = readFile.Read(readExtraHeader)
	if err != nil {
		return err
	}
	decryptor, err := secretstream.NewDecryptor(readExtraHeader[0:n], dk)
	// read each block and decrypt, writing the result to the decrypted file
	for {
		n, err = readFile.Read(readCtxt)
		msg, tag, err := decryptor.Pull(readCtxt[0:n], nil)
		if err != nil {
			return err
		}
		_, err = decryptedFile.Write(msg)
		if err != nil {
			return err
		}
		if tag == secretstream.TagFinal {
			break
		}
	}
	decryptedFile.Close()
	return nil
}
