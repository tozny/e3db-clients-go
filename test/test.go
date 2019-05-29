package test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-go/v2"
)

// MakeE3DBAccount attempts to create a valid e3db account returning the root client config for the created account and error (if any).
func MakeE3DBAccount(t *testing.T, accounter *accountClient.E3dbAccountClient, accountTag string, authNHost string) (e3dbClients.ClientConfig, *accountClient.CreateAccountResponse, error) {
	var accountClientConfig = e3dbClients.ClientConfig{
		Host:      accounter.Host,
		AuthNHost: authNHost,
	}
	var accountResponse *accountClient.CreateAccountResponse
	// Generate info for creating a new account
	const saltSize = 16
	saltSeed := [saltSize]byte{}
	_, err := rand.Read(saltSeed[:])
	if err != nil {
		t.Errorf("Failed creating salt: %s", err)
		return accountClientConfig, accountResponse, err
	}
	salt := base64.RawURLEncoding.EncodeToString(saltSeed[:])
	publicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	backupPublicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	backupSigningKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	createAccountParams := accountClient.CreateAccountRequest{
		Profile: accountClient.Profile{
			Name:               accountTag,
			Email:              fmt.Sprintf("test+%s@test.com", accountTag),
			AuthenticationSalt: salt,
			EncodingSalt:       salt,
			SigningKey: accountClient.EncryptionKey{
				Ed25519: publicKey,
			},
			PaperAuthenticationSalt: salt,
			PaperEncodingSalt:       salt,
			PaperSigningKey: accountClient.EncryptionKey{
				Ed25519: publicKey,
			},
		},
		Account: accountClient.Account{
			Company: "ACME Testing",
			Plan:    "free0",
			PublicKey: accountClient.ClientKey{
				Curve25519: backupPublicKey,
			},
			SigningKey: accountClient.EncryptionKey{
				Ed25519: backupSigningKey,
			},
		},
	}
	// Create an account and client for that account using the specified params
	ctx := context.TODO()
	accountResponse, err = accounter.CreateAccount(ctx, createAccountParams)
	if err != nil {
		t.Errorf("Error %s creating account with params %+v\n", err, createAccountParams)
		return accountClientConfig, accountResponse, err
	}
	accountClientConfig.APIKey = accountResponse.Account.Client.APIKeyID
	accountClientConfig.APISecret = accountResponse.Account.Client.APISecretKey
	return accountClientConfig, accountResponse, err
}
