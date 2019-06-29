package test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/clientServiceClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
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
	ctx := context.Background()
	accountResponse, err = accounter.CreateAccount(ctx, createAccountParams)
	if err != nil {
		t.Errorf("Error %s creating account with params %+v\n", err, createAccountParams)
		return accountClientConfig, accountResponse, err
	}
	accountClientConfig.APIKey = accountResponse.Account.Client.APIKeyID
	accountClientConfig.APISecret = accountResponse.Account.Client.APISecretKey
	return accountClientConfig, accountResponse, err
}

// RegisterClient is a helper method to generate a client with client service,
// returns a registration response and an empty config for said client.
// On error t.Fatal is called halting test execution.
func RegisterClient(t *testing.T, clientServiceHost string, registrationToken string, clientName string) (*clientServiceClient.ClientRegisterResponse, e3dbClients.ClientConfig) {
	// init empty config to make registration requests
	var registrationResponse *clientServiceClient.ClientRegisterResponse
	userClientConfig := e3dbClients.ClientConfig{
		Host: clientServiceHost,
	}
	publicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed generating public key pair %s", err)
	}
	signingKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed generating signing key pair %s", err)
	}
	unAuthedClientServiceClient := clientServiceClient.New(userClientConfig)
	// Register user
	userRegister := clientServiceClient.ClientRegisterRequest{
		RegistrationToken: registrationToken,
		Client: clientServiceClient.ClientRegisterInfo{
			Name:        clientName,
			Type:        "general",
			PublicKeys:  map[string]string{"curve25519": publicKey},
			SigningKeys: map[string]string{"ed25519": signingKey},
		},
	}
	ctx := context.Background()
	registrationResponse, err = unAuthedClientServiceClient.Register(ctx, userRegister)
	if err != nil {
		t.Fatalf("unable to register user %+v, err: %s\n", userRegister, err)
	}
	userClientConfig.Host = ""                     // clear host, make user define
	userClientConfig.AuthNHost = clientServiceHost // client service is now auth-service
	userClientConfig.APIKey = registrationResponse.APIKeyID
	userClientConfig.APISecret = registrationResponse.APISecret
	return registrationResponse, userClientConfig
}

func CreateRegistrationToken(t *testing.T, queenAccountClient *accountClient.E3dbAccountClient, accountServiceJWT string, clientServiceHost string) string {
	createRegParams := accountClient.CreateRegistrationTokenRequest{
		AccountServiceToken: accountServiceJWT,
		TokenPermissions: accountClient.TokenPermissions{
			Enabled: true,
			OneTime: false,
		},
	}
	// create registration token
	ctx := context.Background()
	createdTokenResp, err := queenAccountClient.CreateRegistrationToken(ctx, createRegParams)
	if err != nil {
		t.Fatalf("could not create registration token %s\n", err)
	}
	return createdTokenResp.Token
}

func MakeClientWriterForRecordType(pdsUser pdsClient.E3dbPDSClient, clientID string, recordType string) (string, error) {
	ctx := context.TODO()
	putEAKParams := pdsClient.PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	resp, err := pdsUser.PutAccessKey(ctx, putEAKParams)
	if err != nil {
		return "", err
	}
	return resp.EncryptedAccessKey, err
}

func WriteRandomRecordForUser(user pdsClient.E3dbPDSClient, recordType string, writerID string) (*pdsClient.Record, error) {
	ctx := context.TODO()
	data := map[string]string{"data": "unencrypted"}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: writerID,
			UserID:   writerID,
			Plain:    map[string]string{"key": "value"},
		},
	}
	return user.WriteRecord(ctx, recordToWrite)
}
