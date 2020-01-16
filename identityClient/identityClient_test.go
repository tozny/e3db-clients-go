package identityClient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/e3db-go/v2"
)

var (
	toznyCyclopsHost            = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	internalIdentityServiceHost = os.Getenv("E3DB_IDENTITY_SERVICE_HOST")
	e3dbAuthHost                = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost             = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey                  = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret               = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID                = os.Getenv("E3DB_CLIENT_ID")
	bootstrapPublicSigningKey   = os.Getenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	bootstrapPrivateSigningKey  = os.Getenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	ValidAccountClientConfig    = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbIdentityHost          = toznyCyclopsHost
	ValidIdentityClientConfig = e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	BootIdentityClientConfig = e3dbClients.ClientConfig{
		ClientID:  e3dbClientID,
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbIdentityHost,
		AuthNHost: e3dbAuthHost,
		SigningKeys: e3dbClients.SigningKeys{
			Public: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: bootstrapPublicSigningKey,
			},
			Private: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: bootstrapPrivateSigningKey,
			},
		},
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
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	describedRealm, err := identityServiceClient.DescribeRealm(testContext, realm.Name)
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
	describedRealm, err := identityServiceClient.DescribeRealm(testContext, realm.Name)
	if err != nil {
		t.Fatalf("error %s describing realm %+v using %+v", err, realm, identityServiceClient)
	}
	if describedRealm.Name != realm.Name || describedRealm.Active != realm.Active {
		t.Errorf("expected %+v to equal %+v", describedRealm, realm)
	}
	err = identityServiceClient.DeleteRealm(testContext, realm.Name)
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
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
		RealmName:              realm.Name,
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

func TestIdentityLoginWithRegisteredIdentity(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestIdentityLoginWithRegisteredIdentity"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	registeredIdentityClientConfig := e3dbClients.ClientConfig{
		Host:        e3dbIdentityHost,
		SigningKeys: signingKeys,
		ClientID:    identity.Identity.ToznyID.String(),
	}
	registeredIdentityClient := New(registeredIdentityClientConfig)
	_, err = registeredIdentityClient.IdentityLogin(testContext, realm.Name)
	if err != nil {
		t.Fatalf("error %s logging in with registered identity %+v using  %+v", err, identity.Identity, registeredIdentityClient)
	}
}

func TestInternalIdentityLoginWithAuthenticatedRealmIdentity(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestInternalIdentityLoginWithAuthenticatedRealmIdentity"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	registeredIdentityClientConfig := e3dbClients.ClientConfig{
		Host:        internalIdentityServiceHost,
		SigningKeys: signingKeys,
	}
	registeredIdentityClient := New(registeredIdentityClientConfig)
	registeredIdentityInternalAuthenticationContext := e3dbClients.ToznyAuthenticatedClientContext{
		ClientID: identity.Identity.ToznyID,
	}
	registeredIdentityInternalAuthHeader, err := json.Marshal(registeredIdentityInternalAuthenticationContext)
	if err != nil {
		t.Fatalf("error %s marshaling %+v to json", err, registeredIdentityInternalAuthenticationContext)
	}
	xToznyAuthNHeader := e3dbClients.ToznyAuthNHeader{
		User: registeredIdentityInternalAuthHeader,
	}
	jsonXToznyAuthNHeader, err := json.Marshal(xToznyAuthNHeader)
	if err != nil {
		t.Fatalf("error %s marshaling %+v to json", err, xToznyAuthNHeader)
	}
	internalIdentityLoginParams := InternalIdentityLoginRequest{
		RealmName:         realm.Name,
		XToznyAuthNHeader: string(jsonXToznyAuthNHeader),
	}
	internalIdentityAuthenticationContext, err := registeredIdentityClient.InternalIdentityLogin(testContext, internalIdentityLoginParams)
	if err != nil {
		t.Fatalf("error %s retrieving internal registered identity %+v using  %+v", err, identity.Identity, registeredIdentityClient)
	}
	if internalIdentityAuthenticationContext.RealmID != realm.ID || internalIdentityAuthenticationContext.RealmName != realm.Name || internalIdentityAuthenticationContext.Active != true {
		t.Fatalf("expected registered identity %+v to be an active member of realm %+v , got  %+v", identity.Identity, realm, internalIdentityAuthenticationContext)
	}
}

func TestRegisterRealmBrokerIdentityWithCreatedRealm(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestRegisterRealmBrokerIdentityWithCreatedRealm"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
	realmBackupIdentityParams := RegisterRealmBrokerIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	_, err = identityServiceClient.RegisterRealmBrokerIdentity(testContext, realmBackupIdentityParams)
	if err != nil {
		t.Fatalf("error %s setting realm backup identity using %+v %+v", err, identityServiceClient, realmBackupIdentityParams)
	}
}

// func TestPushChallenge(t *testing.T) {
// 	identityServiceClient := New(BootIdentityClientConfig)
// 	sessionID := uuid.New()
// 	userChallenge := UserChallengePushRequest{
// 		SessionID: sessionID.String(),
// 		Challenge: "challenge random",
// 		Username:  "Freud",
// 		Realm:     "TestRegisterUserDevice3",
// 	}
// 	err := identityServiceClient.ChallengePushRequest(context.Background(), userChallenge)
// 	if err != nil {
// 		t.Fatalf("error making challenge call %+v", err)

// 	}
// }

// func TestPushAndCompleteChallenge(t *testing.T) {
// 	identityServiceClient := New(BootIdentityClientConfig)
// 	sessionID := uuid.New()
// 	userChallenge := UserChallengePushRequest{
// 		SessionID: sessionID.String(),
// 		Challenge: "challengerandom",
// 		Username:  "Freud",
// 		Realm:     "TestRegisterUserDevice3",
// 	}
// 	err := identityServiceClient.ChallengePushRequest(context.Background(), userChallenge)
// 	if err != nil {
// 		t.Fatalf("error making challenge call %+v", err)

// 	}
// }

func TestRegisterUserDevice(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	// Create Realm
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "testregisteruserdevice4"
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	defer identityServiceClient.DeleteRealm(testContext, realmName)
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}

	// Obtain registration token and register identity
	identityName := "freud"
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
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: publicKey},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	registeredIdentityClientConfig := e3dbClients.ClientConfig{
		Host:        toznyCyclopsHost,
		SigningKeys: signingKeys,
		ClientID:    identity.Identity.ToznyID.String(),
	}
	registeredIdentityClient := New(registeredIdentityClientConfig)

	// Register device to identity client
	tempSigningKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error generating temp signing keys %s", err)
	}
	permanentSigningKeys, _ := e3dbClients.GenerateSigningKeys()
	t.Fatalf("Permanent Signing keys %+v", permanentSigningKeys)

	initiateRegisterDeviceRequest := InitiateRegisterDeviceRequest{
		TempPublicKey: tempSigningKeys.Public.Material,
	}
	resp, err := registeredIdentityClient.InitiateRegisterUserDeviceRequest(context.Background(), initiateRegisterDeviceRequest)
	if err != nil {
		t.Fatalf("Failed to initiate register user device %s\n", err)
	}

	now := time.Now().Unix()
	privateKeyBytes, _ := base64.RawURLEncoding.DecodeString(tempSigningKeys.Private.Material)
	challenge := fmt.Sprintf("%s@%d", permanentSigningKeys.Public.Material, now)
	signedChallengeBytes := ed25519.Sign(privateKeyBytes, []byte(challenge))
	signedChallenge := base64.RawURLEncoding.EncodeToString(signedChallengeBytes)

	registerDeviceRequest := CompleteUserDeviceRegisterRequest{
		RegistrationID:  resp.RegistrationID,
		SignedChallenge: signedChallenge,
		SignedTime:      now,

		OneSignalID:     "109081cd-38c6-4429-ba0d-3f283576c42b",
		DeviceID:        "Somedeviceid",
		DeviceName:      "SomeDeviceName",
		DevicePublicKey: permanentSigningKeys.Public.Material,
	}

	err = registeredIdentityClient.CompleteRegisterUserDeviceRequest(context.Background(), registerDeviceRequest)
	if err != nil {
		t.Fatalf("Failed to complete register user device %s\n", err)
	}

	bootIdentityServiceClient := New(BootIdentityClientConfig)
	userChallenge := UserChallengePushRequest{
		Title:    "Test",
		Body:     "Push notification",
		Question: "Do you approve this test?",
		Username: identityName,
		Realm:    realmName,
	}
	challengeResp, err := bootIdentityServiceClient.ChallengePushRequest(context.Background(), userChallenge)
	if err != nil {
		t.Fatalf("error making challenge call %+v", err)
	}

	rawChallenge := fmt.Sprintf("%s@%d", challengeResp.Challenge, now)
	t.Errorf("this is the raw challnege %s", rawChallenge)
	permanentPrivateKeyBytes, _ := base64.RawURLEncoding.DecodeString(permanentSigningKeys.Private.Material)
	signedChallengeBytes = ed25519.Sign(permanentPrivateKeyBytes, []byte(rawChallenge))
	signedChallenge = base64.RawURLEncoding.EncodeToString(signedChallengeBytes)

	completeChallenge := CompleteChallengeRequest{
		ChallengeID:     challengeResp.ChallengeID,
		SignedChallenge: signedChallenge,
		SignedTime:      now,
	}
	err = anonymousIdentityServiceClient.CompleteChallengeRequest(context.Background(), completeChallenge)
	if err != nil {
		t.Fatalf("error completing challenge call %+v", err)
	}

	err = anonymousIdentityServiceClient.IsChallengeCompleteRequest(context.Background(), challengeResp.ChallengeID)
	if err != nil {
		t.Fatalf("error checking if challenge completed %+v", err)
	}
}

func TestFulfillChallenge(t *testing.T) {
	challengeID := "a780e9ef-33af-4914-bc4b-cfae51fd7910"
	challenge := "YTk4ZDI5ZWUtZDg4OS00ODFiLWJkOWUtYzIyYTU2ZjFmN2E4"
	now := time.Now().Unix()
	rawChallenge := fmt.Sprintf("%s@%d", challenge, now)

	permanentPrivateKeyBytes, _ := base64.RawURLEncoding.DecodeString("G1UkYrgxYfgSnU0MtoHRtzlm-ikFqBRb4hqB63E6nMBwVJZkCVhS3uBQuDgJL2eX2Jy7f4ZbPTbIBh9ppowCKQ")
	signedChallengeBytes := ed25519.Sign(permanentPrivateKeyBytes, []byte(rawChallenge))
	signedChallenge := base64.RawURLEncoding.EncodeToString(signedChallengeBytes)

	completeChallenge := CompleteChallengeRequest{
		ChallengeID:     challengeID,
		SignedChallenge: signedChallenge,
		SignedTime:      now,
	}

	err := anonymousIdentityServiceClient.CompleteChallengeRequest(context.Background(), completeChallenge)
	if err != nil {
		t.Fatalf("error completing challenge call %+v", err)
	}
}
