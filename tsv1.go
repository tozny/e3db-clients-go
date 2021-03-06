package e3dbClients

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
	sodium "golang.org/x/crypto/nacl/sign"
)

const (
	HashingAlgorithm     = "BLAKE2B"
	SignatureType        = "ED25519"
	AuthenticationMethod = "TSV1-" + SignatureType + "-" + HashingAlgorithm // TSV1-ED25519-BLAKE2B
	PublicKeyBytes       = 32
	PrivateKeyBytes      = 64
	Blake2BBytes         = 32
	AuthorizationHeader  = "Authorization"
)

var (
	ErrorPrivateSigningKeyRequired = errors.New("private signing key is required but was not provided")
	ErrorPublicSigningKeyRequired  = errors.New("public signing key is required but was not provided")
)

// SignRequest signs (using Tozny Signature Version 1) the request
// with the provided public and private sodium signing keys, returning error (if any).
// If successful, SignRequest will overwrite any existing `AuthorizationHeader`.
func SignRequest(r *http.Request, signingKeys SigningKeys, timestamp int64, clientID string) error {
	publicKey := &[PublicKeyBytes]byte{}
	rawKeyBytes, err := base64.RawURLEncoding.DecodeString(signingKeys.Public.Material)
	if err != nil {
		return err
	}
	copied := copy(publicKey[:], rawKeyBytes)
	if copied != PublicKeyBytes {
		return fmt.Errorf("invalid number %d of public signing key byte, required %d", copied, PublicKeyBytes)
	}
	privateKey := &[PrivateKeyBytes]byte{}
	rawKeyBytes, err = base64.RawURLEncoding.DecodeString(signingKeys.Private.Material)
	if err != nil {
		return err
	}
	copied = copy(privateKey[:], rawKeyBytes)
	if copied != PrivateKeyBytes {
		return fmt.Errorf("invalid number %d of private signing key byte, required %d", copied, PrivateKeyBytes)
	}
	callMethod := r.Method
	callPath := r.URL.EscapedPath()
	queryString := r.URL.Query().Encode()
	nonce := uuid.New()
	publicB64 := base64.RawURLEncoding.EncodeToString(publicKey[:])
	headerString := fmt.Sprintf("%s; %s; %d; %s; %s", AuthenticationMethod, publicB64, timestamp, nonce, "uid:"+clientID)
	strToSign := fmt.Sprintf("%s; %s; %s; %s", callPath, queryString, callMethod, headerString)
	h, err := blake2b.New(Blake2BBytes, nil)
	if err != nil {
		return err
	}
	h.Write([]byte(strToSign))
	hashToSign := h.Sum(nil)
	fullSignature := sodium.Sign(nil, hashToSign, privateKey)
	detachedSignature := fullSignature[:sodium.Overhead]
	signatureB64 := base64.RawURLEncoding.EncodeToString(detachedSignature)
	authHeader := fmt.Sprintf("%s; %s", headerString, signatureB64)
	r.Header.Set(AuthorizationHeader, authHeader)
	return err
}
