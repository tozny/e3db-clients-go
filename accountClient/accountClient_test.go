package accountClient_test

import (
	"context"
	"os"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

var (
	e3dbAuthHost      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAccountHostV2 = os.Getenv("E3DB_ACCOUNT2_SERVICE_HOST")
	e3dbAPIKey        = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret     = os.Getenv("E3DB_API_KEY_SECRET")
	testCtx           = context.Background()
	ValidClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	ValidClientConfigV2 = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHostV2,
		AuthNHost: e3dbAuthHost,
	}
)

/*
func TestCreatingRegistrationTokens(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidClientConfig)
	ctx := context.Background()
	accountTag := uuid.New().String()
	_, response, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Failure Creating New Account\n")
	}

	accountServiceToken := response.AccountServiceToken

	// create registration token
	createRegistrationTokenParams := accountClient.CreateRegistrationTokenRequest{
		AccountServiceToken: accountServiceToken,
		TokenPermissions: accountClient.TokenPermissions{
			Enabled:      true,
			OneTime:      false,
			AllowedTypes: []string{"general"},
		},
		Name: "General Admission",
	}
	createdRegistrationToken, err := accounter.CreateRegistrationToken(ctx, createRegistrationTokenParams)
	if err != nil {
		t.Fatalf("Error %+v creating registration token %+v", err, createRegistrationTokenParams)
	}

	listedRegistrationTokens, err := accounter.ListRegistrationTokens(ctx, accountServiceToken)

	if err != nil {
		t.Fatalf("Error %+v listing registration tokens", err)
	}

	var listed bool
	for _, listedRegistrationToken := range *listedRegistrationTokens {
		if listedRegistrationToken.Name == createdRegistrationToken.Name {
			if listedRegistrationToken.Token == createdRegistrationToken.Token {
				listed = true
				break
			}
		}
	}

	if !listed {
		t.Fatalf("Created token%+v \n not listed in accounts registration tokens %+v", createdRegistrationToken, *listedRegistrationTokens)
	}
}

func TestDeletingRegistrationTokens(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidClientConfig)
	ctx := context.Background()
	accountTag := uuid.New().String()
	_, createAccountResponse, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Failure Creating New Account\n")
	}

	accountServiceToken := createAccountResponse.AccountServiceToken

	// create registration token
	createRegistrationTokenParams := accountClient.CreateRegistrationTokenRequest{
		AccountServiceToken: accountServiceToken,
		TokenPermissions: accountClient.TokenPermissions{
			Enabled:      true,
			OneTime:      false,
			AllowedTypes: []string{"general"},
		},
		Name: "General Admission",
	}
	createRegistrationTokenResponse, err := accounter.CreateRegistrationToken(ctx, createRegistrationTokenParams)
	if err != nil {
		t.Fatalf("Error %+v creating registration token %+v", err, createRegistrationTokenParams)
	}

	// deleted created registration token
	deleteRegistrationTokenParams := accountClient.DeleteRegistrationTokenRequest{
		AccountServiceToken: accountServiceToken,
		Token:               createRegistrationTokenResponse.Token,
	}
	err = accounter.DeleteRegistrationToken(ctx, deleteRegistrationTokenParams)
	if err != nil {
		t.Fatalf("Error %+v \n deleting registration token %+v\n with params %+v\n", err, createRegistrationTokenResponse, deleteRegistrationTokenParams)
	}
	// verify its deleted from the api
	listedRegistrationTokens, err := accounter.ListRegistrationTokens(ctx, accountServiceToken)

	if err != nil {
		t.Fatalf("Error %+v listing registration tokens", err)
	}

	var listed bool
	for _, listedRegistrationToken := range *listedRegistrationTokens {
		if listedRegistrationToken.Name == createRegistrationTokenResponse.Name {
			if listedRegistrationToken.Token == createRegistrationTokenResponse.Token {
				listed = true
				break
			}
		}
	}

	if listed {
		t.Fatalf("Deleted token%+v \n listed in accounts registration tokens %+v", createRegistrationTokenResponse, *listedRegistrationTokens)
	}
}

func TestInternalGetClientAccountReturnsClientsAccountId(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidClientConfig)
	ctx := context.TODO()
	accountTag := uuid.New().String()
	_, response, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Failure Creating New Account\n")
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

func TestInternalAccountDeleteReturnsSuccess(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidClientConfig)
	accountTag := uuid.New().String()
	_, response, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Failure Creating New Account\n %+v", err)
	}
	// Delete Account
	err = accounter.InternalAccountDelete(testCtx, response.Profile.AccountID)
	if err != nil {
		t.Fatalf("Failure Removing Account\n: %+v", err)
	}
}
*/
