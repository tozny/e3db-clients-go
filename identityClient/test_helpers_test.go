package identityClient

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/storageClient"
	"github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/utils-go"
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

func createIdentityServiceClient(t *testing.T) E3dbIdentityClient {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	return identityServiceClient
}

func createIdentityServiceClientAndToken(t *testing.T) (E3dbIdentityClient, string) {
	accountTag := uuid.New().String()
	queenClientInfo, accountInfo, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)

	queenClientInfo.Host = e3dbAccountHost
	accountToken := accountInfo.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, registrationToken)
	}
	return identityServiceClient, registrationToken
}

func createFakePasswordNoteForIdentity(clientConfig e3dbClients.ClientConfig, recipientKey, username, realmName string) (*storageClient.Note, error) {
	noteName, err := e3dbClients.DeriveIdentityCredentialsNoteName(username, realmName)
	data := map[string]string{
		"key1": "rawnote",
		"key2": "unprocessednote",
		"key3": "organicnote",
	}
	if err != nil {
		return nil, err
	}
	ak := e3dbClients.RandomSymmetricKey()
	eak, err := e3dbClients.EncryptAccessKey(ak, clientConfig.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	encryptedData := e3dbClients.EncryptData(data, ak)
	return &storageClient.Note{
		Mode:                "Sodium",
		IDString:            noteName,
		ClientID:            clientConfig.ClientID,
		RecipientSigningKey: recipientKey,
		WriterSigningKey:    clientConfig.SigningKeys.Public.Material,
		WriterEncryptionKey: clientConfig.EncryptionKeys.Public.Material,
		EncryptedAccessKey:  eak,
		Type:                "Integration Test",
		Data:                *encryptedData,
		Plain:               map[string]string{"extra1": "not encrypted", "extra2": "more plain data"},
		Signature:           "signed",
		MaxViews:            5,
	}, err
}

func createIdentityAndRegisterWithRealm(t *testing.T, realm *Realm, registrationToken string, clientConfig e3dbClients.ClientConfig) *RegisterIdentityResponse {
	identityName := uuid.New().String()
	identityEmail := "test-emails-group+" + identityName + "tozny.com"
	identityFirstName := "Sigmund"
	identityLastName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			Email:       identityEmail,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Errorf("RegisterIdentity Error: %+v\n", err)
	}
	// Write a password note for the new identity
	StorageClient := storageClient.New(clientConfig)
	passwordNote, err := createFakePasswordNoteForIdentity(clientConfig, clientConfig.SigningKeys.Public.Material, identityName, realm.Name)
	if err != nil {
		t.Fatalf("error %+v creating password note for identity with name %s in realm %s", err, identityName, realm.Name)
	}
	_, err = StorageClient.WriteNote(testContext, *passwordNote)
	if err != nil {
		t.Fatalf("error %+v writing password note %+v", err, passwordNote)
	}
	return identity
}

func registerIdentity(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, registrationToken string) (*RegisterIdentityResponse, E3dbIdentityClient) {
	identityTag := uuid.New().String()
	identityName := "Freud" + identityTag
	identityEmail := "test-emails-group+freud+" + identityTag + "@tozny.com"
	identityFirstName := "Sigmund"
	identityLastName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realmName,
		Identity: Identity{
			Name:        identityName,
			Email:       identityEmail,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
		},
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

	return identity, registeredIdentityClient
}

func uniqueString(prefix string) string {
	rand.Seed(time.Now().UnixNano())

	return fmt.Sprintf("%s%d", prefix, rand.Int())
}

func createRealmWithParams(t *testing.T, identityServiceClient E3dbIdentityClient, params CreateRealmRequest) *Realm {
	var realm *Realm
	var err error
	retries := 2

	ready := func() bool {
		realm, err = identityServiceClient.CreateRealm(testContext, params)
		if err != nil {
			t.Logf("FAILED to create realm. Will try %d times in total.", retries+1)
			return false
		}
		return true
	}

	success := utils.Await(ready, retries)
	if !success {
		t.Fatalf("%s realm creation failed after %d retries; %+v %+v\n", err, retries, params, identityServiceClient)
	}

	return realm
}

func createRealm(t *testing.T, identityServiceClient E3dbIdentityClient) *Realm {
	unique := uniqueString("realm")
	params := CreateRealmRequest{
		RealmName:     unique,
		SovereignName: "realmsovereign",
	}

	return createRealmWithParams(t, identityServiceClient, params)
}

func createRealmApplication(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string) *Application {
	unique := uniqueString("realmapplication")
	params := CreateRealmApplicationRequest{
		RealmName: realmName,
		Application: Application{
			ClientID: unique,
			Name:     unique,
			Active:   true,
			Protocol: ProtocolOIDC,
			OIDCSettings: ApplicationOIDCSettings{
				RootURL: "https://jenkins.acme.com",
			},
		},
	}

	application, err := identityServiceClient.CreateRealmApplication(testContext, params)

	if err != nil {
		t.Fatalf("error %s creating realm %s application %+v using %+v", err, realmName, params, identityServiceClient)
	}

	return application
}

func createRealmApplicationRole(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, applicationID string, roleName string) *ApplicationRole {
	params := CreateRealmApplicationRoleRequest{
		RealmName:     realmName,
		ApplicationID: applicationID,
		ApplicationRole: ApplicationRole{
			Name:        roleName,
			Description: fmt.Sprintf("%s description", roleName),
		},
	}

	applicationRole, err := identityServiceClient.CreateRealmApplicationRole(testContext, params)

	if err != nil {
		t.Fatalf("error %s creating realm application role %+v using %+v", err, params, identityServiceClient)
	}

	return applicationRole
}

func listRealmApplicationRoles(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, applicationID string) []ApplicationRole {
	params := ListRealmApplicationRolesRequest{
		RealmName:     realmName,
		ApplicationID: applicationID,
	}
	applicationRoles, err := identityServiceClient.ListRealmApplicationRoles(testContext, params)

	if err != nil {
		t.Fatalf("error listing realm application roles: %+v", err)
	}

	return applicationRoles.ApplicationRoles
}

func groupMembership(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, identity string) []Group {
	params := RealmIdentityRequest{
		RealmName:  realmName,
		IdentityID: identity,
	}

	groups, err := identityServiceClient.GroupMembership(testContext, params)

	if err != nil {
		t.Fatalf("error listing default realm groups: %+v", err)
	}

	return groups.Groups
}

func updateGroupMembership(t *testing.T, identityServiceClient E3dbIdentityClient, method string, realmName string, identity string, groups []string) {
	params := UpdateIdentityGroupMembershipRequest{
		RealmName:  realmName,
		IdentityID: identity,
		Groups:     groups,
	}
	var err error
	switch method {
	case "join":
		err = identityServiceClient.JoinGroups(testContext, params)
		break
	case "leave":
		err = identityServiceClient.LeaveGroups(testContext, params)
		break
	case "update":
		err = identityServiceClient.UpdateGroupMembership(testContext, params)
		break
	default:
		err = fmt.Errorf("Unknown method for update default realm groups")
	}

	if err != nil {
		t.Fatalf("error updating default realm groups with method %q and request %+v: %+v", method, params, err)
	}
}

func createRealmGroup(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, groupName string) *Group {
	params := CreateRealmGroupRequest{
		RealmName: realmName,
		Group: Group{
			Name: groupName,
		},
	}

	group, err := identityServiceClient.CreateRealmGroup(testContext, params)

	if err != nil {
		t.Fatalf("error creating realm group %+v: %+v", params, err)
	}

	return group
}

func listRealmGroups(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string) []Group {
	params := ListRealmGroupsRequest{
		RealmName: realmName,
	}

	groups, err := identityServiceClient.ListRealmGroups(testContext, params)

	if err != nil {
		t.Fatalf("error listing realm application roles: %+v", err)
	}

	return groups.Groups
}

func listDefaultRealmGroups(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string) []Group {
	params := ListRealmGroupsRequest{
		RealmName: realmName,
	}

	groups, err := identityServiceClient.ListRealmDefaultGroups(testContext, params)

	if err != nil {
		t.Fatalf("error listing default realm groups: %+v", err)
	}

	return groups.Groups
}

func updateDefaultRealmGroups(t *testing.T, identityServiceClient E3dbIdentityClient, method string, realmName string, groups []string) {
	params := UpdateGroupListRequest{
		RealmName: realmName,
		Groups:    groups,
	}
	var err error
	switch method {
	case "add":
		err = identityServiceClient.AddRealmDefaultGroups(testContext, params)
		break
	case "remove":
		err = identityServiceClient.RemoveRealmDefaultGroups(testContext, params)
		break
	case "replace":
		err = identityServiceClient.ReplaceRealmDefaultGroups(testContext, params)
		break
	default:
		err = fmt.Errorf("Unknown method for update default realm groups")
	}

	if err != nil {
		t.Fatalf("error updating default realm groups with method %q and request %+v: %+v", method, params, err)
	}
}
