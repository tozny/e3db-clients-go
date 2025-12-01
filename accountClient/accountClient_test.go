package accountClient_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/identityClient"
	"github.com/tozny/e3db-clients-go/test"
	e3dbTest "github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/utils-go"
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

// TestAccountDeleteReturnsSuccess calls account delete
func TestAccountDeleteReturnsSuccess(t *testing.T) {
	// Create Account
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	// Account Client V1 and V2
	queenAccountClientV2 := accountClient.NewV2(queenClientInfo)
	queenAccountClient := accountClient.New(queenClientInfo)
	accountUUID := uuid.MustParse(createAccountResponse.Profile.AccountID)
	// Create Identity Client
	identityServiceClient := identityClient.New(queenClientInfo)
	realmName := fmt.Sprintf("TestAccountDeleteWorks%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	// Delete Realm After Test
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	// Registration Token
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	identityName := "Katie"
	identityEmail := "katie@tozny.com"
	identityFirstName := "Katie"
	identityLastName := "Rock"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: identityClient.Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: cyclopsServiceHost,
	}
	anonClient := identityClient.New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	// Delete Account Request
	request := accountClient.DeleteAccountRequestData{
		AccountID: accountUUID,
	}
	err = queenAccountClientV2.DeleteAccount(testContext, request)
	if err != nil {
		t.Fatalf("Error deleting account %+v", err)
	}

}

// TestAccountDeleteSuccessCanRecreateAccountWithSameEmailReturns200 calls account delete and creates an account with the same email
func TestAccountDeleteSuccessCanRecreateAccountWithSameEmailReturns200(t *testing.T) {
	// Create Account
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	randomUUID := uuid.New().String()
	accountEmail := fmt.Sprintf("test-emails-group+%s@tozny.com", randomUUID)
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccountWithEmail(t, &registrationClient, randomUUID, accountEmail, cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	// Account Client V1 and V2
	queenAccountClientV2 := accountClient.NewV2(queenClientInfo)
	queenAccountClient := accountClient.New(queenClientInfo)
	accountUUID := uuid.MustParse(createAccountResponse.Profile.AccountID)
	// Create Identity Client
	identityServiceClient := identityClient.New(queenClientInfo)
	realmName := fmt.Sprintf("TestAccountDeleteWorks%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	// Delete Realm After Test
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	// Registration Token
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	identityName := "Katie"
	identityEmail := "katie@tozny.com"
	identityFirstName := "Katie"
	identityLastName := "Rock"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: identityClient.Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: cyclopsServiceHost,
	}
	anonClient := identityClient.New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	// Delete Account Request
	request := accountClient.DeleteAccountRequestData{
		AccountID: accountUUID,
	}
	err = queenAccountClientV2.DeleteAccount(testContext, request)
	if err != nil {
		t.Fatalf("Error deleting account %+v", err)
	}
	// Recreate Account with same Email
	ready := func() bool {
		registrationClientTest := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
		_, _, err = e3dbTest.CreateE3DBAccountWithEmail(t, &registrationClientTest, randomUUID, accountEmail, cyclopsServiceHost)
		if err != nil {
			return false
		}
		return true
	}
	retries := 3
	success := utils.Await(ready, retries)
	if !success {
		t.Fatalf("Error %s making  account With same Email checked %+v times ", err, retries)
	}

}

// TestAccountDeleteSuccessCanRecreateAccountAndRealmsWithSameEmailReturns200 calls account delete and creates an account with the same email
func TestAccountDeleteSuccessCanRecreateAccountAndRealmsWithSameEmailReturns200(t *testing.T) {
	// Create Account
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	randomUUID := uuid.New().String()
	accountEmail := fmt.Sprintf("test-emails-group+%s@tozny.com", randomUUID)
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccountWithEmail(t, &registrationClient, randomUUID, accountEmail, cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	// Account Client V1 and V2
	queenAccountClientV2 := accountClient.NewV2(queenClientInfo)
	queenAccountClient := accountClient.New(queenClientInfo)
	accountUUID := uuid.MustParse(createAccountResponse.Profile.AccountID)
	// Create Identity Client
	identityServiceClient := identityClient.New(queenClientInfo)
	realmName := fmt.Sprintf("TestAccountandRealm%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	accountToken := createAccountResponse.AccountServiceToken
	// Registration Token
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	identityName := "Katie"
	identityEmail := "katie@tozny.com"
	identityFirstName := "Katie"
	identityLastName := "Rock"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: identityClient.Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: cyclopsServiceHost,
	}
	anonClient := identityClient.New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	// Delete Account Request
	request := accountClient.DeleteAccountRequestData{
		AccountID: accountUUID,
	}
	err = queenAccountClientV2.DeleteAccount(testContext, request)
	if err != nil {
		t.Fatalf("Error deleting account %+v", err)
	}
	// Recreate Account with same Email
	for {
		var errors error
		registrationClientTest := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
		queenClientInfo, _, errors = e3dbTest.CreateE3DBAccountWithEmail(t, &registrationClientTest, randomUUID, accountEmail, cyclopsServiceHost)
		if errors == nil {
			break
		}
		time.Sleep(retryTimeout)
	}
	identityServiceClient = identityClient.New(queenClientInfo)
	params = identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm again
	_, err = identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("Realm Ceation Failed %+v", err)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
}

func TestAccountDeleteSuccessCanRecreateAccountAndRealmsAndIdentityWithSameEmailReturns200(t *testing.T) {
	// Create Account
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
	randomUUID := uuid.New().String()
	accountEmail := fmt.Sprintf("test-emails-group+%s@tozny.com", randomUUID)
	queenClientInfo, createAccountResponse, err := e3dbTest.MakeE3DBAccountWithEmail(t, &registrationClient, randomUUID, accountEmail, cyclopsServiceHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = cyclopsServiceHost
	// Account Client V1 and V2
	queenAccountClientV2 := accountClient.NewV2(queenClientInfo)
	queenAccountClient := accountClient.New(queenClientInfo)
	accountUUID := uuid.MustParse(createAccountResponse.Profile.AccountID)
	// Create Identity Client
	identityServiceClient := identityClient.New(queenClientInfo)
	realmName := fmt.Sprintf("TestAccountandRealm%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	accountToken := createAccountResponse.AccountServiceToken
	// Registration Token
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	identityName := "Katie"
	identityEmail := "katie@tozny.com"
	identityFirstName := "Katie"
	identityLastName := "Rock"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: identityClient.Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: cyclopsServiceHost,
	}
	anonClient := identityClient.New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	// Delete Account Request
	request := accountClient.DeleteAccountRequestData{
		AccountID: accountUUID,
	}
	err = queenAccountClientV2.DeleteAccount(testContext, request)
	if err != nil {
		t.Fatalf("Error deleting account %+v", err)
	}
	// Recreate Account with same Email
	for {
		var errors error
		registrationClientTest := accountClient.New(e3dbClients.ClientConfig{Host: cyclopsServiceHost})
		queenClientInfo, createAccountResponse, errors = e3dbTest.CreateE3DBAccountWithEmail(t, &registrationClientTest, randomUUID, accountEmail, cyclopsServiceHost)
		if errors == nil {
			break
		}
		time.Sleep(retryTimeout)
	}
	identityServiceClient = identityClient.New(queenClientInfo)
	params = identityClient.CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create a Realm again

	realm, err = identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("Create realm failed %+v", err)
	}
	defer identityServiceClient.DeleteRealm(testContext, realmName)

	// Registration Token
	queenAccountClient = accountClient.New(queenClientInfo)
	registrationToken, err = test.CreateRegistrationToken(&queenAccountClient, createAccountResponse.AccountServiceToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	// Register same identity
	registerParams = identityClient.RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: identityClient.Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
}
