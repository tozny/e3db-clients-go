package accountClient_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
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

func TestInitEmailUpdateWithValidAccountSucceeds(t *testing.T) {
	// make internal account client (v1)
	registrationClient := accountClient.New(ValidClientConfig)
	_, resp, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	currentTime := time.Now().Local()
	// make internal account client (v2)
	updateClient := accountClient.NewV2(ValidClientConfigV2)
	newEmailReq := accountClient.InitiateUpdateEmailRequest{
		AccountID:    resp.Profile.AccountID,
		CurrentEmail: resp.Profile.Email,
		NewEmail:     "test" + uuid.New().String() + "@example.com",
		CreatedAt:    currentTime,
		CoolOffEnd:   currentTime.Add(time.Hour * 24),
	}
	// Make request to post / initiate the  email update
	response, err := updateClient.InitiateEmailUpdate(testCtx, newEmailReq)
	if err != nil {
		t.Fatalf("Failed to initiate email update \n Email Req: (%+v) \n error %+v", newEmailReq, err)
	}
	// Verify that the AccountID returned matches the client
	if response.AccountID.String() != newEmailReq.AccountID {
		t.Fatalf("AccountID (%+v) passed in does not match AccountID in response (%+v) for request (%+v)", response.AccountID.String(), newEmailReq.AccountID, newEmailReq)
	}
}

func TestInitEmailUpdateWithTwoReqsFails(t *testing.T) {
	registrationClient := accountClient.New(ValidClientConfig)
	_, resp, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	currentTime := time.Now().Local()
	updateClient := accountClient.NewV2(ValidClientConfigV2)
	newEmailReq := accountClient.InitiateUpdateEmailRequest{
		AccountID:    resp.Profile.AccountID,
		CurrentEmail: resp.Profile.Email,
		NewEmail:     "test" + uuid.New().String() + "@example.com",
		CreatedAt:    currentTime,
		CoolOffEnd:   currentTime.Add(time.Hour * 24),
	}
	// Make request to post / initiate the email update & verify it's successful
	_, err = updateClient.InitiateEmailUpdate(testCtx, newEmailReq)
	if err != nil {
		t.Fatalf("Failed to initiate email update \n Email Req: (%+v) \n error %+v", newEmailReq, err)
	}
	// Make request to post / initiate the same email update again & verify it fails
	_, err = updateClient.InitiateEmailUpdate(testCtx, newEmailReq)
	if err == nil {
		t.Fatalf("A second email update was initiated with same AccountID\n Email Req: (%+v) \n error %+v", newEmailReq, err)
	}
}
