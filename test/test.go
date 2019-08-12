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
		t.Errorf("Failed creating encryption key pair salt: %s", err)
		return accountClientConfig, accountResponse, err
	}
	salt := base64.RawURLEncoding.EncodeToString(saltSeed[:])
	publicKey, privateEncryptionKey, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Errorf("Failed generating signing key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	signingKey := signingKeys.Public.Material
	backupSigningKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Errorf("Failed generating backup signing key pair %s", err)
		return accountClientConfig, accountResponse, err
	}
	backupSigningKey := backupSigningKeys.Public.Material
	createAccountParams := accountClient.CreateAccountRequest{
		Profile: accountClient.Profile{
			Name:               accountTag,
			Email:              fmt.Sprintf("test+%s@example.com", accountTag),
			AuthenticationSalt: salt,
			EncodingSalt:       salt,
			SigningKey: accountClient.EncryptionKey{
				Ed25519: signingKey,
			},
			PaperAuthenticationSalt: salt,
			PaperEncodingSalt:       salt,
			PaperSigningKey: accountClient.EncryptionKey{
				Ed25519: backupSigningKey,
			},
		},
		Account: accountClient.Account{
			Company: "ACME Testing",
			Plan:    "free0",
			PublicKey: accountClient.ClientKey{
				Curve25519: publicKey,
			},
			SigningKey: accountClient.EncryptionKey{
				Ed25519: signingKey,
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
	accountClientConfig.ClientID = accountResponse.Account.Client.ClientID
	accountClientConfig.APIKey = accountResponse.Account.Client.APIKeyID
	accountClientConfig.APISecret = accountResponse.Account.Client.APISecretKey
	accountClientConfig.SigningKeys = signingKeys
	accountClientConfig.EncryptionKeys = e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Material: privateEncryptionKey,
			Type:     e3dbClients.DefaultEncryptionKeyType},
		Public: e3dbClients.Key{
			Material: publicKey,
			Type:     e3dbClients.DefaultEncryptionKeyType},
	}
	return accountClientConfig, accountResponse, err
}

// RegisterClient is a helper method to generate a client with the client service,
// returns a registration response and a config for the created client without the Host field populated.
func RegisterClient(ctx context.Context, clientServiceHost string, registrationToken string, clientName string) (*clientServiceClient.ClientRegisterResponse, e3dbClients.ClientConfig, error) {
	// init empty config to make registration requests
	var registrationResponse *clientServiceClient.ClientRegisterResponse
	userClientConfig := e3dbClients.ClientConfig{
		Host: clientServiceHost,
	}
	publicKey, privateEncryptionKey, err := e3db.GenerateKeyPair()
	if err != nil {
		return registrationResponse, userClientConfig, err
	}
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		return registrationResponse, userClientConfig, fmt.Errorf("error: %s generating signing key pair", err)
	}
	signingKey := signingKeys.Public.Material
	unAuthedClientServiceClient := clientServiceClient.New(userClientConfig)
	// Register user
	userRegister := clientServiceClient.ClientRegisterRequest{
		RegistrationToken: registrationToken,
		Client: clientServiceClient.ClientRegisterInfo{
			Name:        clientName,
			Type:        "general",
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{e3dbClients.DefaultSigningKeyType: signingKey},
		},
	}
	registrationResponse, err = unAuthedClientServiceClient.Register(ctx, userRegister)
	if err != nil {
		return registrationResponse, userClientConfig, err
	}
	userClientConfig.Host = ""                     // clear host, and force the user to define
	userClientConfig.AuthNHost = clientServiceHost // client service is responsible for authenticating requests
	userClientConfig.ClientID = registrationResponse.Client.ClientID.String()
	userClientConfig.APIKey = registrationResponse.APIKeyID
	userClientConfig.APISecret = registrationResponse.APISecret
	userClientConfig.SigningKeys = signingKeys
	userClientConfig.EncryptionKeys = e3dbClients.EncryptionKeys{
		Private: e3dbClients.Key{
			Material: privateEncryptionKey,
			Type:     e3dbClients.DefaultEncryptionKeyType},
		Public: e3dbClients.Key{
			Material: publicKey,
			Type:     e3dbClients.DefaultEncryptionKeyType},
	}
	return registrationResponse, userClientConfig, err
}

func CreatePDSClient(ctx context.Context, pdsHost string, clientHost string, registrationToken string, clientName string, recordType string) (pdsClient.E3dbPDSClient, string, e3dbClients.ClientConfig, error) {
	var userClientID string
	var userPDSClient pdsClient.E3dbPDSClient
	registrationResponse, userClientConfig, err := RegisterClient(ctx, clientHost, registrationToken, clientName)
	if err != nil {
		return userPDSClient, userClientID, userClientConfig, err
	}
	userClientConfig.Host = pdsHost
	userPDSClient = pdsClient.New(userClientConfig)
	userClientID = registrationResponse.ClientID.String()
	_, err = MakeClientWriterForRecordType(userPDSClient, userClientID, recordType)
	return userPDSClient, userClientID, userClientConfig, err
}

// CreateRegistrationToken makes a registration token for a queenAccount
// requires the accountServiceJWT recieved from successfully completing an account-service challenge.
func CreateRegistrationToken(queenAccountClient *accountClient.E3dbAccountClient, accountServiceJWT string) (string, error) {
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
		return "", err
	}
	return createdTokenResp.Token, err
}

// MakeClientWriterForRecordType places an EAK for a record type for a pdsUser.
func MakeClientWriterForRecordType(pdsUser pdsClient.E3dbPDSClient, clientID string, recordType string) (*pdsClient.PutAccessKeyResponse, error) {
	ctx := context.Background()
	putEAKParams := pdsClient.PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	return pdsUser.PutAccessKey(ctx, putEAKParams)
}

// WriteRandomRecordForUser creates a record with junk data and meta for a pdsUser by default.
func WriteRandomRecordForUser(user pdsClient.E3dbPDSClient, recordType string, writerID string, data *map[string]string, meta *map[string]string) (*pdsClient.Record, error) {
	ctx := context.Background()
	if data == nil {
		data = &map[string]string{"data": "unencrypted"}
	}
	if meta == nil {
		meta = &map[string]string{"key": "value"}
	}
	recordToWrite := pdsClient.WriteRecordRequest{
		Data: *data,
		Metadata: pdsClient.Meta{
			Type:     recordType,
			WriterID: writerID,
			UserID:   writerID,
			Plain:    *meta,
		},
	}
	return user.WriteRecord(ctx, recordToWrite)
}
