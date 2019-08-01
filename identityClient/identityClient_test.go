package identityClient

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/e3db-go/v2"
)

var (
	toznyCyclopsHost         = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	e3dbAuthHost             = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost          = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey               = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret            = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID             = os.Getenv("E3DB_CLIENT_ID")
	ValidAccountClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbIdentityHost          = toznyCyclopsHost
	ValidIdentityClientConfig = e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonymousIdentityServiceClient = New(ValidIdentityClientConfig)
	testContext                    = context.TODO()
	accountServiceClient           = accountClient.New(ValidAccountClientConfig)
)

func TestHealthCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymousIdentityServiceClient.HealthCheck(testContext)
	if err != nil {
		t.Errorf("%s health check failed using %+v\n", err, anonymousIdentityServiceClient)
	}
}

func TestServiceCheckPassesIfServiceIsRunning(t *testing.T) {
	err := anonymousIdentityServiceClient.ServiceCheck(testContext)
	if err != nil {
		t.Errorf("%s service check failed using %+v\n", err, anonymousIdentityServiceClient)
	}
}

func TestCreateRealmCreatesRealmWithUserDefinedName(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestCreateRealmCreatesRealmWithUserDefinedName"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Errorf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.ID)
	if realm.Name != realmName {
		t.Errorf("expected realm name to be %+v , got %+v", realmName, realm)
	}
}

func TestDescribeRealmReturnsDetailsOfCreatedRealm(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestDescribeRealmReturnsDetailsOfCreatedRealm"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.ID)
	describedRealm, err := identityServiceClient.DescribeRealm(testContext, realm.ID)
	if err != nil {
		t.Fatalf("error %s describing realm %+v using %+v", err, realm, identityServiceClient)
	}
	if describedRealm.Name != realm.Name || describedRealm.Active != realm.Active {
		t.Errorf("expected %+v to equal %+v", describedRealm, realm)
	}
}

func TestDeleteRealmDeletesCreatedRealm(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestDescribeRealmReturnsDetailsOfCreatedRealm"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	describedRealm, err := identityServiceClient.DescribeRealm(testContext, realm.ID)
	if err != nil {
		t.Fatalf("error %s describing realm %+v using %+v", err, realm, identityServiceClient)
	}
	if describedRealm.Name != realm.Name || describedRealm.Active != realm.Active {
		t.Errorf("expected %+v to equal %+v", describedRealm, realm)
	}
	err = identityServiceClient.DeleteRealm(testContext, realm.ID)
	if err != nil {
		t.Fatalf("error %s deleting realm %+v", err, realm)
	}
	realms, err := identityServiceClient.ListRealms(testContext)
	if err != nil {
		t.Fatalf("error %s listing realms %+v", err, realm)
	}
	for _, listedRealm := range realms.Realms {
		if realm.ID == listedRealm.ID {
			t.Errorf("expected realm %+v to be deleted, found it in listed realms %+v", realm, realms)
		}
	}
}

func TestRegisterIdentityWithCreatedRealm(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestRegisterIdentityWithCreatedRealm"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.ID)
	identityName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	publicKey, _, err := e3db.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	queenClientInfo.Host = e3dbAccountHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmID:                realm.ID,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
}
