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
	cyclopsServiceHost         = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	e3dbClientID               = os.Getenv("E3DB_CLIENT_ID")
	bootstrapPublicSigningKey  = os.Getenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	bootstrapPrivateSigningKey = os.Getenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	testContext                = context.TODO()
)

//TestAccountDeleteReturnsSuccess calls account delete
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
	accountEmail := fmt.Sprintf("testemail-%s@email.com", randomUUID)
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
