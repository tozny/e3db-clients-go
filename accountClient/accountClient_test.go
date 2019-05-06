package accountClient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-go/v2"
	"os"
	"strings"
	"testing"
)

var (
	e3dbAuthHost      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey        = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret     = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID      = os.Getenv("E3DB_CLIENT_ID")
	ValidClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
)

func TestInternalGetClientAccountReturns404ForClientsWithNoAccount(t *testing.T) {
	// Create internal account client
	accounter := New(ValidClientConfig)
	// Make request to get the account for this internal client(should be non existent)
	ctx := context.TODO()
	_, err := accounter.InternalGetClientAccount(ctx, e3dbClientID)
	if err == nil {
		t.Errorf("Expected error %s trying to get account info for client with no account %+v\n", err, accounter)
	}
	// Verify error is 404/not found
	if !strings.Contains(err.Error(), "http error 404") {
		t.Errorf("Expected 404 response, got %s", err)
	}
}

func TestInternalGetClientAccountReturnsClientsAccountId(t *testing.T) {
	// Create internal account client
	accounter := New(ValidClientConfig)
	// Generate info for creating a new account
	const saltSize = 16
	saltSeed := [saltSize]byte{}
	_, err := rand.Read(saltSeed[:])
	if err != nil {
		t.Errorf("Failed creating salt: %s", err)
	}
	salt := base64.RawURLEncoding.EncodeToString(saltSeed[:])
	publicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating key pair %s", err)
	}
	backupPublicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating key pair %s", err)
	}
	accountTag := uuid.New().String()
	createAccountParams := CreateAccountRequest{
		Profile: Profile{
			Name:               accountTag,
			Email:              fmt.Sprintf("test+%s@test.com", accountTag),
			AuthenticationSalt: salt,
			EncodingSalt:       salt,
			SigningKey: EncryptionKey{
				Ed25519: publicKey,
			},
			PaperAuthenticationSalt: salt,
			PaperEncodingSalt:       salt,
			PaperSigningKey: EncryptionKey{
				Ed25519: publicKey,
			},
		},
		Account: Account{
			Company: "ACME Testing",
			Plan:    "free0",
			PublicKey: ClientKey{
				Curve25519: backupPublicKey,
			},
		},
	}
	// Create an account and client for that account using the specified params
	ctx := context.TODO()
	response, internalError := accounter.CreateAccount(ctx, createAccountParams)
	err = e3dbClients.FlatMapInternalError(*internalError)
	if err != nil {
		t.Errorf("Error %s creating account with params %+v\n", err, createAccountParams)
	}
	accountID := response.Profile.AccountID
	clientID := response.Account.Client.ClientID
	// Make request to lookup the account for this account's client
	account, internalError := accounter.InternalGetClientAccount(ctx, clientID)
	err = e3dbClients.FlatMapInternalError(*internalError)
	if err != nil {
		t.Errorf("Error %s trying to get account info for client %+v\n", err, accounter)
	}
	// Verify correct account id for this client is returned
	if account.AccountID != accountID {
		t.Errorf("Expected account id to be %s, got %s", accountID, account.AccountID)
	}
}
