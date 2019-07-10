package e3dbClients_test

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	"github.com/tozny/e3db-clients-go/test"
	"os"
	"testing"
)

var (
	e3dbPDSHost          = os.Getenv("E3DB_STORAGE_SERVICE_HOST")
	e3dbClientHost       = os.Getenv("E3DB_CLIENT_SERVICE_HOST")
	e3dbAuthHost         = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAPIKey           = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret        = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbAccountHost      = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	ValidPDSClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbPDSHost,
		AuthNHost: e3dbAuthHost,
	}
	ValidBootAccountClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,

		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	bootAccountClient         = accountClient.New(ValidBootAccountClientConfig)
	validPDSRegistrationToken string
	defaultPDSUserRecordType  = "integration_tests"
	validPDSUser              pdsClient.E3dbPDSClient
	validPDSUserConfig        e3dbClients.ClientConfig
	validPDSUserID            string
)

//TestMain gives all tests access to a client "validPDSUser" who is authorized to write to a default record type.
func TestMain(m *testing.M) {
	err := setup()
	if err != nil {
		fmt.Printf("Could perform setup for tests due to %s", err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(code)
}

func setup() error {
	accountTag := uuid.New().String()
	queenAccountConfig, createAccountResp, err := test.MakeE3DBAccount(&testing.T{}, &bootAccountClient, accountTag, e3dbAuthHost)
	if err != nil {
		return err
	}
	queenAccountClient := accountClient.New(queenAccountConfig)
	accountServiceJWT := createAccountResp.AccountServiceToken

	queenAccountConfig.Host = e3dbPDSHost
	validPDSUser = pdsClient.New(queenAccountConfig)
	validPDSUserID = createAccountResp.Account.Client.ClientID
	validPDSUserConfig = queenAccountConfig
	validPDSRegistrationToken, err = test.CreateRegistrationToken(&queenAccountClient, accountServiceJWT)
	return err
}

func TestValidateTokenReturnsValidResultsForValidExternalClientToken(t *testing.T) {
	bootAuthConfig := e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		AuthNHost: e3dbAuthHost,
	}
	bootAuthClient := authClient.New(bootAuthConfig)
	validPDSUserConfig.Host = e3dbAuthHost
	externalClientAuthClient := authClient.New(validPDSUserConfig)

	ctx := context.Background()
	userToken, err := externalClientAuthClient.GetToken(ctx)
	if err != nil {
		t.Errorf("Error: %v fetching token for user %v", err, externalClientAuthClient)
	}
	validateTokenRequestParams := authClient.ValidateTokenRequest{Token: userToken.AccessToken, Internal: false}
	response, err := bootAuthClient.ValidateToken(ctx, validateTokenRequestParams)
	if err != nil {
		t.Errorf("Error: %s calling ValidateToken", err)
	}
	if response.Valid != true {
		t.Errorf("Expected token to be valid, got %+v", response)
	}
	if response.ClientId != validPDSUserID {
		t.Errorf("Expected token to belong to %v valid, got %+v", validPDSUserID, response)
	}
}
