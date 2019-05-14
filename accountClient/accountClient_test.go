package accountClient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-go/v2"
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
	ctx := context.TODO()
	response, err := makeNewAccount(t, ctx, accounter)
	if err != nil {
		t.Errorf("Failure Creating New Account\n")
		return
	}
	accountID := response.Profile.AccountID
	clientID := response.Account.Client.ClientID
	// Make request to lookup the account for this account's client
	account, err := accounter.InternalGetClientAccount(ctx, clientID)
	if err != nil {
		t.Errorf("Error %s trying to get account info for client %+v\n", err, accounter)
	}
	// Verify correct account id for this client is returned
	if account.AccountID != accountID {
		t.Errorf("Expected account id to be %s, got %s", accountID, account.AccountID)
	}
}

func TestInternalGetAccountInfoForAccount(t *testing.T) {
	// Create internal account client
	accounter := New(ValidClientConfig)
	// Create new account with stripe id
	ctx := context.TODO()
	response, err := makeNewAccount(t, ctx, accounter)
	if err != nil {
		t.Errorf("Failure Creating New Account\n")
		return
	}
	accountID := response.Profile.AccountID
	// Make request to lookup the account for this account's client
	stripeResponse, err := accounter.InternalGetAccountInfo(ctx, accountID)
	if err != nil {
		t.Errorf("Error %s trying to get stripe id for account %+v\n", err, accounter)
	}
	// Verify a string that looks like a stripe id is returned
	if !strings.HasPrefix(stripeResponse.StripeID, "cus_") {
		t.Errorf("Expected stripe ID to look like a stripe id, but was \"%v\" <- in quotes", stripeResponse.StripeID)
	}
}

func TestInternalGetStripeIDReturns404ForAccountsWithoutStripeID(t *testing.T) {
	// Create internal account client
	accounter := New(ValidClientConfig)
	// Make request to get the account for a random accountID
	ctx := context.TODO()
	_, err := accounter.InternalGetAccountInfo(ctx, uuid.New().String())
	if err == nil {
		t.Errorf("Expected error %s trying to get account info for client with no account %+v\n", err, accounter)
	}
	// Verify error is 404/not found
	if !strings.Contains(err.Error(), "http error 404") {
		t.Errorf("Expected 404 response, got %s", err)
	}
}

func makeNewAccount(t *testing.T, ctx context.Context, accounter E3dbAccountClient) (*CreateAccountResponse, error) {
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
	response, err := accounter.CreateAccount(ctx, createAccountParams)
	if err != nil {
		t.Errorf("Error %s creating account with params %+v\n", err, createAccountParams)
	}
	return response, err
}
