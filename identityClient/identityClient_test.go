package identityClient

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
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

func createIdentityAndRegisterWithRealm(t *testing.T, realm *Realm, registrationToken string) *RegisterIdentityResponse {
	identityName := uuid.New().String()
	identityEmail := identityName + "@email.com"
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
	return identity
}

// VerifyIncludeDetailsForDetailedIdentity checks that a DetailedFederatedIdentity has additional details after a
// sync that set the IncludeDetails filter
func VerifyIncludeDetailsForDetailedIdentity(federatedIdentities []DetailedFederatedIdentity) error {
	var err error
	for _, identity := range federatedIdentities {
		if identity.Active == false {
			err = errors.New("expected DetailedFederatedIdentity to be Active")
			break
		}
		if identity.Attributes == nil {
			err = errors.New("expected DetailedFederatedIdentity to have Attributes")
			break
		}
		if identity.Roles.ClientRoles == nil {
			err = errors.New("expected Client Roles for DetailedFederatedIdentity")
			break
		}
		if identity.Roles.RealmRoles == nil {
			err = errors.New("expected Realm Roles for DetailedFederatedIdentity")
			break
		}
		if identity.Group == nil {
			err = errors.New("expected non-nil Group infromation for DetailedFederatedIdentity")
			break
		}
		if identity.SubjectID == "" {
			err = errors.New("expected Subject ID for DetailedFederatedIdentity")
			break
		}
		if identity.LastName == "" {
			err = errors.New("expected last name for DetailedfederatedIdentity")
			break
		}
		if identity.FirstName == "" {
			err = errors.New("expected first name for DetailedfederatedIdentity")
			break
		}
	}
	return err
}

func syncContainsIdentity(syncedIdentities []DetailedFederatedIdentity, createdIdentityUsername string) bool {
	for _, a := range syncedIdentities {
		if a.Username == createdIdentityUsername {
			return true
		}
	}
	return false
}

func ConfigureAndCreateAFederatedRealm(t *testing.T) (*Realm, E3dbIdentityClient, string, map[string]string) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := fmt.Sprintf("realmName%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	realm := createRealmWithParams(t, identityServiceClient, params)

	tozIDFederationEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		TozIDFederationEnabled: &(tozIDFederationEnabled),
	}

	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}

	requestParam := InitializeFederationConnectionRequest{
		RealmName:        realm.Name,
		FederationSource: "tozid",
	}
	response, err := identityServiceClient.InitiateFederationConnection(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error [%+v] Initiating Federation Connection for Realm %+v", err, requestParam)
	}
	if response.RealmName != realmName {
		t.Fatalf("Error Expected %+v, Recieved %+v", realmName, response.RealmName)
	}
	if response.ConnectionID == uuid.Nil {
		t.Fatalf("Error Expected a valid UUID, Recieved %+v", response.ConnectionID)
	}
	if response.APICredential == "" {
		t.Fatalf("Error Expected a credential, Recieved %+v", response.APICredential)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	credentials := make(map[string]string)
	credentials[TozIDFederationAuthHeader] = response.APICredential

	return realm, identityServiceClient, registrationToken, credentials
}

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
	realmName := uniqueString("TestCreateRealmCreatesRealmWithUserDefinedName")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
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
	realmName := uniqueString("TestDescribeRealmReturnsDetailsOfCreatedRealm")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
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
	realmName := uniqueString("TestDescribeRealmReturnsDetailsOfCreatedRealm")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
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
	realmName := uniqueString("TestRegisterIdentityWithCreatedRealm")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	identityName := "Freud"
	identityEmail := "test-emails-group+freud@tozny.com"
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
	realmName := uniqueString("TestIdentityLoginWithRegisteredIdentity")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	identityName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
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
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
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

func TestRegisterRealmBrokerIdentityWithCreatedRealm(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestRegisterRealmBrokerIdentityWithCreatedRealm")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	identityName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
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
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material}},
	}
	_, err = identityServiceClient.RegisterRealmBrokerIdentity(testContext, realmBackupIdentityParams)
	if err != nil {
		t.Fatalf("error %s setting realm backup identity using %+v %+v", err, identityServiceClient, realmBackupIdentityParams)
	}
}

func TestGetToznyHostedBrokerInfo(t *testing.T) {
	accountTag := uuid.New().String()

	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)

	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost

	identityServiceClient := New(queenClientInfo)

	toznyHostedBrokerInfo, err := identityServiceClient.GetToznyHostedBrokerInfo(testContext)

	if err != nil {
		t.Fatalf("Error %s fetching tozny hosted broker info", err)
	}

	if toznyHostedBrokerInfo.ClientID.String() == "" || toznyHostedBrokerInfo.PublicSigningKey == "" || toznyHostedBrokerInfo.PublicKey == "" {
		t.Fatalf("Incomplete Tozny hosted broker info %+v", toznyHostedBrokerInfo)
	}
}

func TestApplicationCRD(t *testing.T) {
	accountTag := uuid.New().String()

	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)

	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestApplicationCRD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	autoGeneratedApplications, err := identityServiceClient.ListRealmApplications(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v applications using %+v", err, realm, identityServiceClient)
	}

	realmApplicationCreateParams := CreateRealmApplicationRequest{
		RealmName: realm.Name,
		Application: Application{
			ClientID: "jenkins-oidc-app",
			Name:     "Jenkins Your Build Is Ready",
			Active:   true,
			Protocol: ProtocolOIDC,
			OIDCSettings: ApplicationOIDCSettings{
				RootURL: "https://jenkins.acme.com",
			},
		},
	}

	application, err := identityServiceClient.CreateRealmApplication(testContext, realmApplicationCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v application %+v using %+v", err, realm, realmApplicationCreateParams, identityServiceClient)
	}

	describedApplication, err := identityServiceClient.DescribeRealmApplication(testContext, DescribeRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm %+v application %+v using %+v", err, realm, application, identityServiceClient)
	}

	if describedApplication.Name != realmApplicationCreateParams.Application.Name {
		t.Fatalf("expected described application %+v to have same name as it was created with %+v", describedApplication, realmApplicationCreateParams)
	}

	listedApplications, err := identityServiceClient.ListRealmApplications(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v applications using %+v", err, realm, identityServiceClient)
	}

	if len(listedApplications.Applications) != 1+len(autoGeneratedApplications.Applications) {
		t.Fatalf("expected only created application %+v to be listed, got %+v", application, listedApplications)
	}

	err = identityServiceClient.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	if err != nil {
		t.Fatalf("error %s deleting realm %+v application %+v using %+v", err, realm, realmApplicationCreateParams, identityServiceClient)
	}

	listedApplications, err = identityServiceClient.ListRealmApplications(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v applications using %+v", err, realm, identityServiceClient)
	}

	if len(listedApplications.Applications) != len(autoGeneratedApplications.Applications) {
		t.Fatalf("expected deleted application %+v not to be listed, got %+v", application, listedApplications)
	}
}

func TestProviderCRD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)

	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestProviderCRD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	autoGeneratedProviders, err := identityServiceClient.ListRealmProviders(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v providers using %+v", err, realm, identityServiceClient)
	}

	realmProviderCreateParams := CreateRealmProviderRequest{
		RealmName: realm.Name,
		Provider: Provider{
			Type:             LDAPProviderType,
			Name:             "LDAP Identity Provider",
			Active:           true,
			Priority:         0,
			ImportIdentities: true,
			ConnectionSettings: ProviderConnectionSettings{
				Type:                  ActiveDirectoryProviderType,
				IdentityNameAttribute: "cn",
				RDNAttribute:          "cn",
				UUIDAttribute:         "objectGUID",
				IdentityObjectClasses: []string{
					"person",
					"organizationalPerson",
					"user",
				},
				ConnectionURL:      "ldap://test.local",
				IdentityDN:         "cn=users,dc=tozny,dc=local",
				AuthenticationType: ProviderConnectionSimpleType,
				BindDN:             "TOZNY\\administrator",
				BindCredential:     "password",
				SearchScope:        1,
				TrustStoreSPIMode:  ProviderTrustStoreLDAPOnlyMode,
				ConnectionPooling:  true,
				Pagination:         true,
			},
		},
	}

	provider, err := identityServiceClient.CreateRealmProvider(testContext, realmProviderCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v provider %+v using %+v", err, realm, realmProviderCreateParams, identityServiceClient)
	}

	describedProvider, err := identityServiceClient.DescribeRealmProvider(testContext, DescribeRealmProviderRequest{
		RealmName:  realm.Name,
		ProviderID: provider.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm %+v provider %+v using %+v", err, realm, provider, identityServiceClient)
	}

	if describedProvider.Name != realmProviderCreateParams.Provider.Name {
		t.Fatalf("expected described provider %+v to have same name as it was created with %+v", describedProvider, realmProviderCreateParams)
	}

	listedProviders, err := identityServiceClient.ListRealmProviders(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v providers using %+v", err, realm, identityServiceClient)
	}

	if len(listedProviders.Providers) != 1+len(autoGeneratedProviders.Providers) {
		t.Fatalf("expected only created provider %+v to be listed, got %+v", provider, listedProviders)
	}

	err = identityServiceClient.DeleteRealmProvider(testContext, DeleteRealmProviderRequest{
		RealmName:  realm.Name,
		ProviderID: provider.ID,
	})

	if err != nil {
		t.Fatalf("error %s deleting realm %+v provider %+v using %+v", err, realm, realmProviderCreateParams, identityServiceClient)
	}

	listedProviders, err = identityServiceClient.ListRealmProviders(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v providers using %+v", err, realm, identityServiceClient)
	}

	if len(listedProviders.Providers) != len(autoGeneratedProviders.Providers) {
		t.Fatalf("expected deleted provider %+v not to be listed, got %+v", provider, listedProviders)
	}
}

func TestProviderMapperCRD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)

	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestProviderMapperCRD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	realmProviderCreateParams := CreateRealmProviderRequest{
		RealmName: realm.Name,
		Provider: Provider{
			Type:             LDAPProviderType,
			Name:             "LDAP Identity Provider",
			Active:           true,
			Priority:         0,
			ImportIdentities: true,
			ConnectionSettings: ProviderConnectionSettings{
				Type:                  ActiveDirectoryProviderType,
				IdentityNameAttribute: "cn",
				RDNAttribute:          "cn",
				UUIDAttribute:         "objectGUID",
				IdentityObjectClasses: []string{
					"person",
					"organizationalPerson",
					"user",
				},
				ConnectionURL:      "ldap://test.local",
				IdentityDN:         "cn=users,dc=tozny,dc=local",
				AuthenticationType: ProviderConnectionSimpleType,
				BindDN:             "TOZNY\\administrator",
				BindCredential:     "password",
				SearchScope:        1,
				TrustStoreSPIMode:  ProviderTrustStoreLDAPOnlyMode,
				ConnectionPooling:  true,
				Pagination:         true,
			},
		},
	}

	provider, err := identityServiceClient.CreateRealmProvider(testContext, realmProviderCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v provider %+v using %+v", err, realm, realmProviderCreateParams, identityServiceClient)
	}

	defer identityServiceClient.DeleteRealmProvider(testContext, DeleteRealmProviderRequest{
		RealmName:  realm.Name,
		ProviderID: provider.ID,
	})

	listRealmProviderMappersRequest := ListRealmProviderMappersRequest{
		RealmName:  realm.Name,
		ProviderID: provider.ID,
	}

	autoGeneratedProviderMappers, err := identityServiceClient.ListRealmProviderMappers(testContext, listRealmProviderMappersRequest)

	if err != nil {
		t.Fatalf("error %s listing realm %+v provider %+v mappers using %+v", err, realm, provider, identityServiceClient)
	}

	realmProviderMapperCreateParams := CreateRealmProviderMapperRequest{
		RealmName:  realm.Name,
		ProviderID: provider.ID,
		ProviderMapper: ProviderMapper{
			Type:               LDAPGroupProviderMapperType,
			Name:               "ldap-group-mapper",
			GroupsDN:           "ou=groups,dc=tozny,dc=local",
			GroupNameAttribute: "cn",
			GroupObjectClasses: []string{
				"group",
			},
			PreserveGroupInheritance:        true,
			IgnoreMissingGroups:             false,
			MemberOfAttribute:               ProviderDefaultMemberOfAttribute,
			MembershipAttribute:             "member",
			MembershipAttributeType:         "DN",
			Mode:                            ProviderMapperReadOnlyMode,
			MembershipIdentityAttribute:     "cn",
			IdentityGroupsRetrievalStrategy: ProviderMappperGroupsByMemberAttributeRetrievalStrategy,
			DropMissingGroupsOnSync:         false,
		},
	}

	providerMapper, err := identityServiceClient.CreateRealmProviderMapper(testContext, realmProviderMapperCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v provider mapper %+v using %+v", err, realm, realmProviderMapperCreateParams, identityServiceClient)
	}

	describedProviderMapper, err := identityServiceClient.DescribeRealmProviderMapper(testContext, DescribeRealmProviderMapperRequest{
		RealmName:        realm.Name,
		ProviderID:       provider.ID,
		ProviderMapperID: providerMapper.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm %+v provider mapper %+v using %+v", err, realm, providerMapper, identityServiceClient)
	}

	if describedProviderMapper.Name != realmProviderMapperCreateParams.ProviderMapper.Name {
		t.Fatalf("expected described provider mapper %+v to have same name as it was created with %+v", describedProviderMapper, realmProviderMapperCreateParams)
	}

	listedProviderMappers, err := identityServiceClient.ListRealmProviderMappers(testContext, listRealmProviderMappersRequest)

	if err != nil {
		t.Fatalf("error %s listing realm %+v provider mappers using %+v", err, realm, identityServiceClient)
	}

	if len(listedProviderMappers.ProviderMappers) != 1+len(autoGeneratedProviderMappers.ProviderMappers) {
		t.Fatalf("expected created provider mapper %+v to be listed in provider mappers, got %+v", providerMapper, listedProviderMappers)
	}

	err = identityServiceClient.DeleteRealmProviderMapper(testContext, DeleteRealmProviderMapperRequest{
		RealmName:        realm.Name,
		ProviderID:       provider.ID,
		ProviderMapperID: providerMapper.ID,
	})

	if err != nil {
		t.Fatalf("error %s deleting realm %+v provider mapper %+v using %+v", err, realm, providerMapper, identityServiceClient)
	}

	listedProviderMappers, err = identityServiceClient.ListRealmProviderMappers(testContext, listRealmProviderMappersRequest)

	if err != nil {
		t.Fatalf("error %s listing realm %+v provider mappers using %+v", err, realm, identityServiceClient)
	}

	if len(listedProviderMappers.ProviderMappers) != len(autoGeneratedProviderMappers.ProviderMappers) {
		t.Fatalf("expected deleted provider mapper %+v not to be listed, got %+v", providerMapper, listedProviderMappers)
	}
}

func TestListIdentitiesPaginates(t *testing.T) {
	// Test Parameters
	pages := 2
	perPage := 2
	totalIdentities := pages * perPage
	// New Account
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost

	// Registration Token
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	// Client for registration calls
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)

	// New Realm
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestListIdentities")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Register multiple identities
	// These identities can use the same keys...
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %q generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	for i := 0; i < totalIdentities; i++ {
		identityName := fmt.Sprintf("testListIDs%d", i)
		identityEmail := fmt.Sprintf("test-emails-group+testListID+%d@tozny.com", i)
		identityFirstName := fmt.Sprintf("Test%d", i)
		identityLastName := "User"
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
		_, err = anonClient.RegisterIdentity(testContext, registerParams)
		if err != nil {
			t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
		}
	}
	// Verify initial pages
	first := 0
	for i := 0; i < pages; i++ {
		listRequest := ListIdentitiesRequest{
			RealmName: realmName,
			First:     first,
			Max:       perPage,
		}
		identities, err := identityServiceClient.ListIdentities(testContext, listRequest)
		first = identities.Next
		if err != nil {
			t.Fatalf("unable to fetch identity list from realm %q - first %d max %d: %+v", realmName, first, perPage, err)
		}
		if identities.Identities[0].Email == "" {
			t.Fatalf("Error: Expected Identities to have email, Got %+v", identities)
		}

		if len(identities.Identities) != perPage {
			t.Fatalf("identity count incorrect with first %d in realm %q mismatch, expected 1, got %d", first, realmName, len(identities.Identities))
		}
	}
	// Verify last page (there will always be one more because of the admin user)
	listRequest := ListIdentitiesRequest{
		RealmName: realmName,
		First:     1,
		Max:       1,
	}
	identities, err := identityServiceClient.ListIdentities(testContext, listRequest)
	if err != nil {
		t.Fatalf("unable to fetch the last identity list page from realm %q: %+v", realmName, err)
	}
	if len(identities.Identities) != 1 {
		t.Fatalf("identity count incorrect with in realm %q  for the last page, expected 1, got %d", realmName, len(identities.Identities))
	}
}

func TestListIdentitiesRespectsOffest(t *testing.T) {
	// Test Parameters
	createdIdentities := 3
	// New Account
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost

	// Registration Token
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	// Client for registration calls
	anonConfig := e3dbClients.ClientConfig{
		Host: e3dbIdentityHost,
	}
	anonClient := New(anonConfig)

	// New Realm
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestListIdentities")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Register multiple identities
	// These identities can use the same keys...
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %q generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	for i := 0; i < createdIdentities; i++ {
		identityName := fmt.Sprintf("testListIDs%d", i)
		identityEmail := fmt.Sprintf("test-emails-group+testListID+%d@tozny.com", i)
		identityFirstName := fmt.Sprintf("Test%d", i)
		identityLastName := "User"
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
		_, err = anonClient.RegisterIdentity(testContext, registerParams)
		if err != nil {
			t.Fatalf("error %s registering identity using %+v %+v", err, anonClient, registerParams)
		}
	}
	// Verify each page fetched returns different identities
	found := map[string]BasicIdentity{}
	first := 0
	for i := 0; i < createdIdentities+1; i++ {
		startLength := len(found)
		listRequest := ListIdentitiesRequest{
			RealmName: realmName,
			First:     first,
			Max:       1,
		}
		identities, err := identityServiceClient.ListIdentities(testContext, listRequest)
		first = identities.Next
		if err != nil {
			t.Fatalf("unable to fetch identity list from realm %q: %+v", realmName, err)
		}
		if len(identities.Identities) != 1 {
			t.Fatalf("expected to find a single identity but got %d", len(identities.Identities))
		}
		found[identities.Identities[0].ID] = identities.Identities[0]
		if len(found)-startLength != 1 {
			t.Fatalf("expected found length to increase by one from %d now %d. %+v %+v", startLength, len(found), identities.Identities[0], found)
		}
	}
}

func TestIdentityDetails(t *testing.T) {
	// New Account
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost

	// New Realm
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestListIdentities")
	sovereignName := "yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	// Fetch Identity Details for SovereignIdentity
	details, err := identityServiceClient.DescribeIdentity(testContext, realmName, sovereignName)
	if err != nil {
		t.Fatalf("Error %+v while fetching identity %q", err, sovereignName)
	}
	// Validate data is present
	if details.Name != sovereignName {
		t.Errorf("Unexpected name for sovereign: expected %q got %q", sovereignName, details.Name)
	}
	if details.Active != true {
		t.Error("Expected sovereign to be active, but it was not")
	}
	if len(details.Roles.RealmRoles) < 1 {
		t.Errorf("Expected realm roles to have at least one role in it, but it had %d", len(details.Roles.RealmRoles))
	}
	realmManagementRoles, ok := details.Roles.ClientRoles["realm-management"]
	if !ok {
		t.Fatalf("Expected sovereign to have realm-management roles, but they are not found: %+v", details.Roles.ClientRoles)
	}
	found := false
	for _, role := range realmManagementRoles {
		if role.Name == "realm-admin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected sovereign to have the realm-admin role in the realm-management client, but it was not found: %+v", realmManagementRoles)
	}
}

func TestDeleteIdentityRemoves(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	err := client.DeleteIdentity(testContext, RealmIdentityRequest{
		RealmName:  realm.Name,
		IdentityID: identityID,
	})
	if err != nil {
		t.Fatalf("unable to delete identity: %+v", err)
	}
	// Validate the identity is cleaned up
	foundIdentities, err := client.ListIdentities(testContext, ListIdentitiesRequest{
		RealmName: realm.Name,
		Max:       1000,
	})
	if err != nil {
		t.Fatalf("Error %+v while fetching identity %q", err, identityID)
	}
	for _, found := range foundIdentities.Identities {
		if found.Name == identity.Identity.Name {
			t.Fatalf("Found identity %q in realm, but it should have been removed", found.Name)
		}
	}
}

func TestGroupMembershipWorksWhenEmpty(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	groups := groupMembership(t, client, realm.Name, identityID)

	if len(groups) != 0 {
		t.Errorf("expected result to be empty")
	}
}

func TestGroupMembershipReturnsGroups(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	groupName := uniqueString("realm group")
	groupCreated := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   groupCreated.ID,
	})

	// make default group
	updateGroupMembership(t, client, "join", realm.Name, identityID, []string{groupCreated.ID})

	actual := groupMembership(t, client, realm.Name, identityID)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	group := actual[0]

	if group.Name != groupName {
		t.Errorf("expected result group name to be '%s', was '%s'", groupName, group.Name)
	}
}

func TestLeaveGroupsRemovesGroups(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	groupName := uniqueString("realm group")
	groupCreated := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   groupCreated.ID,
	})

	// make default group then remove it
	updateGroupMembership(t, client, "join", realm.Name, identityID, []string{groupCreated.ID})
	updateGroupMembership(t, client, "leave", realm.Name, identityID, []string{groupCreated.ID})

	actual := groupMembership(t, client, realm.Name, identityID)

	if len(actual) != 0 {
		t.Errorf("expected result to have no elements")
	}
}

func TestJoinGroupsAddsGroups(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	group1Name := uniqueString("realm group 1")
	group1 := createRealmGroup(t, client, realm.Name, group1Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group1.ID,
	})
	group2Name := uniqueString("realm group 2")
	group2 := createRealmGroup(t, client, realm.Name, group2Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group2.ID,
	})

	// join a group
	updateGroupMembership(t, client, "join", realm.Name, identityID, []string{group1.ID})
	// join another group
	updateGroupMembership(t, client, "join", realm.Name, identityID, []string{group2.ID})

	actual := groupMembership(t, client, realm.Name, identityID)

	if len(actual) != 2 {
		t.Errorf("expected result to have two elements")
	}

	found := map[string]bool{}
	found[group1Name] = false
	found[group2Name] = false
	for _, group := range actual {
		found[group.Name] = true
	}

	for groupName, isFound := range found {
		if !isFound {
			t.Errorf("did not find %q in returned groups: %+v", groupName, actual)
		}
	}
}

func TestUpdateGroupMemvbershipReplacesGroups(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity, _ := registerIdentity(t, client, realm.Name, registrationToken)
	identityID := identity.Identity.ToznyID.String()

	group1Name := uniqueString("realm group 1")
	group1 := createRealmGroup(t, client, realm.Name, group1Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group1.ID,
	})
	group2Name := uniqueString("realm group 2")
	group2 := createRealmGroup(t, client, realm.Name, group2Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group2.ID,
	})

	// join a group
	updateGroupMembership(t, client, "join", realm.Name, identityID, []string{group1.ID})
	// leave original group and join new group
	updateGroupMembership(t, client, "update", realm.Name, identityID, []string{group2.ID})

	actual := groupMembership(t, client, realm.Name, identityID)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	group := actual[0]

	if group.Name != group2Name {
		t.Errorf("expected result group name to be '%s', was '%s'", group2Name, group.Name)
	}
}

func TestDescribeApplicationRoleReturnsCreatedApplicationRole(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	defer client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	actual, err := client.DescribeRealmApplicationRole(testContext, DescribeRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	if err != nil {
		t.Fatalf("error %s describing realm application role %s using %+v", err, realmApplicationRole.ID, client)
	}

	if len(actual.ID) == 0 {
		t.Errorf("expected result to have ID")
	}
	if actual.Name != roleName {
		t.Errorf("expected result role name to be '%s', was '%s'", roleName, actual.Name)
	}

	roleDescription := roleName + " description"

	if actual.Description != roleDescription {
		t.Errorf("expected result role description to be '%s', was '%s'", roleDescription, actual.Description)
	}
}

func TestListApplicationRoleReturnsOnlyDefaultRoleWhenNoUserProvidedRole(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)

	if len(actual) != 1 {
		t.Errorf("expected 1 default application role, Recieved %+v", actual)
	}
	if actual[0].Name != DefaultUMAProtectionApplicationRole {
		t.Errorf("Expected %+v, Recieved %+v", DefaultUMAProtectionApplicationRole, actual)
	}
}

func TestListApplicationRoleReturnsCreatedApplicationRoles(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	defaultRoles := listRealmApplicationRoles(t, client, realm.Name, application.ID)
	roleName := uniqueString("realm application role")
	_ = createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	defer client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)
	expectedNumberOfAplicationRoles := len(defaultRoles) + 1
	if len(actual) != expectedNumberOfAplicationRoles {
		t.Errorf("expected %d number of realm roles, recieved %+v", expectedNumberOfAplicationRoles, actual)
	}
	roleDescription := roleName + " description"
	var found bool
	for _, role := range actual {
		if role.Name == roleName {
			if role.Description == roleDescription {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("Expected to find role with name %+v and description %+v, In list %+v did not", roleName, roleDescription, actual)
	}
}

func TestDeletedApplicationRoleIsUndescribable(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	roleName := uniqueString("realm application role")
	_ = createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	err := client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	if err != nil {
		t.Errorf("expected no error deleting realm application role, got: %+v", err)
	}

	actual, err := client.DescribeRealmApplicationRole(testContext, DescribeRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	if actual != nil {
		t.Errorf("expected no result when describing deleted realm application role, got %+v", actual)
	}

	if err == nil {
		t.Errorf("expected error when describing deleted realm application role")
	}
}

func TestDeletedApplicationRoleIsNotListed(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})
	defaultRoles := listRealmApplicationRoles(t, client, realm.Name, application.ID)
	roleName := uniqueString("realm application role")
	_ = createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	err := client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:           realm.Name,
		ApplicationID:       application.ID,
		ApplicationRoleName: roleName,
	})

	if err != nil {
		t.Errorf("expected no error deleting realm application role, got: %+v", err)
	}

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)

	if len(actual) != len(defaultRoles) {
		t.Errorf("expected %d after deleting the role created, recieved %+v", len(defaultRoles), actual)
	}
}

func TestDescribeGroupReturnsCreatedGroup(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	group := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	actual, err := client.DescribeRealmGroup(testContext, DescribeRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm group %s using %+v", err, group.ID, client)
	}

	if len(actual.ID) == 0 {
		t.Errorf("expected result to have ID")
	}
	if actual.Name != groupName {
		t.Errorf("expected result group name to be '%s', was '%s'", groupName, actual.Name)
	}
}

func TestListGroupsReturnsNoGroupsWhenThereAreNone(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	actual := listRealmGroups(t, client, realm.Name)

	if len(actual) != 0 {
		t.Errorf("expected 0 groups before creating one")
	}
}

func TestListGroupsReturnsCreatedGroups(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	groupCreated := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   groupCreated.ID,
	})

	actual := listRealmGroups(t, client, realm.Name)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	group := actual[0]

	if group.Name != groupName {
		t.Errorf("expected result group name to be '%s', was '%s'", groupName, group.Name)
	}
}

func TestDeletedGroupIsUndescribable(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	group := createRealmGroup(t, client, realm.Name, groupName)
	err := client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	if err != nil {
		t.Errorf("expected no error deleting group, got: %+v", err)
	}

	actual, err := client.DescribeRealmGroup(testContext, DescribeRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	if actual != nil {
		t.Errorf("expected no result when describing deleted group, got %+v", actual)
	}

	if err == nil {
		t.Errorf("expected error when describing deleted group")
	}
}

func TestDeletedGroupIsNotListed(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	group := createRealmGroup(t, client, realm.Name, groupName)
	err := client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	if err != nil {
		t.Errorf("expected no error deleting realm group, got: %+v", err)
	}

	actual := listRealmGroups(t, client, realm.Name)

	if len(actual) != 0 {
		t.Errorf("expected 0 application roles after deleting the one created")
	}
}

func TestListDefaultGroupsWorksWhenEmpty(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groups := listDefaultRealmGroups(t, client, realm.Name)

	if len(groups) != 0 {
		t.Errorf("expected result to be empty")
	}
}

func TestListDefaultGroupsReturnsDefaultGroups(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	groupCreated := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   groupCreated.ID,
	})

	// make default group
	updateDefaultRealmGroups(t, client, "add", realm.Name, []string{groupCreated.ID})

	actual := listDefaultRealmGroups(t, client, realm.Name)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	group := actual[0]

	if group.Name != groupName {
		t.Errorf("expected result group name to be '%s', was '%s'", groupName, group.Name)
	}
}

func TestRemoveDefaultGroupsRemovesDefaultGroups(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	groupName := uniqueString("realm group")
	groupCreated := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   groupCreated.ID,
	})

	// make default group then remove it
	updateDefaultRealmGroups(t, client, "add", realm.Name, []string{groupCreated.ID})
	updateDefaultRealmGroups(t, client, "remove", realm.Name, []string{groupCreated.ID})

	actual := listDefaultRealmGroups(t, client, realm.Name)

	if len(actual) != 0 {
		t.Errorf("expected result to have no elements")
	}
}

func TestAddDefaultGroupsAddsADefaultGroup(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	group1Name := uniqueString("realm group 1")
	group1 := createRealmGroup(t, client, realm.Name, group1Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group1.ID,
	})
	group2Name := uniqueString("realm group 2")
	group2 := createRealmGroup(t, client, realm.Name, group2Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group2.ID,
	})

	// make default group
	updateDefaultRealmGroups(t, client, "add", realm.Name, []string{group1.ID})
	// add a default group
	updateDefaultRealmGroups(t, client, "add", realm.Name, []string{group2.ID})

	actual := listDefaultRealmGroups(t, client, realm.Name)

	if len(actual) != 2 {
		t.Errorf("expected result to have two elements")
	}

	found := map[string]bool{}
	found[group1Name] = false
	found[group2Name] = false
	for _, group := range actual {
		found[group.Name] = true
	}

	for groupName, isFound := range found {
		if !isFound {
			t.Errorf("did not find %q in returned groups: %+v", groupName, actual)
		}
	}
}

func TestReplaceDefaultGroupsReplacesDefaultGroups(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	group1Name := uniqueString("realm group 1")
	group1 := createRealmGroup(t, client, realm.Name, group1Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group1.ID,
	})
	group2Name := uniqueString("realm group 2")
	group2 := createRealmGroup(t, client, realm.Name, group2Name)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group2.ID,
	})

	// make default group
	updateDefaultRealmGroups(t, client, "add", realm.Name, []string{group1.ID})
	// add a default group
	updateDefaultRealmGroups(t, client, "replace", realm.Name, []string{group2.ID})

	actual := listDefaultRealmGroups(t, client, realm.Name)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	group := actual[0]

	if group.Name != group2Name {
		t.Errorf("expected result group name to be '%s', was '%s'", group2Name, group.Name)
	}
}

func TestGroupRoleMappingCRD(t *testing.T) {
	// Set up identity service client
	client := createIdentityServiceClient(t)
	// Create realm
	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	// Create a realm group
	groupName := uniqueString("realm group")
	group := createRealmGroup(t, client, realm.Name, groupName)
	// Create a realm application
	application := createRealmApplication(t, client, realm.Name)
	// Create a role for the application
	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	// Cache the current role mapping
	groupRoleMapping, err := client.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	// Verify it doesn't have any assigned
	// role mappings for the application yet
	if val, ok := groupRoleMapping.ClientRoles[application.ID]; ok {
		t.Fatalf("Expected group %+v not to have role mappings %+v for application %+v", group, val, application)
	}
	// Add role mapping for application
	addRoleMappingRequest := AddGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
		RoleMapping: RoleMapping{
			ClientRoles: map[string][]Role{
				application.ID: {
					*realmApplicationRole,
				},
			},
		},
	}
	err = client.AddGroupRoleMappings(testContext, addRoleMappingRequest)
	if err != nil {
		t.Fatalf("Error %s adding role mapping %+v to group %+v", err, addRoleMappingRequest, group)
	}
	// Verify application role mapping was added
	groupRoleMapping, err = client.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	applicationRoleMappings, ok := groupRoleMapping.ClientRoles[application.ID]
	if !ok {
		t.Fatalf("Expected group %+v to have role mappings %+v for application %+v", group, groupRoleMapping, application)
	}
	mappedApplicationRole := applicationRoleMappings[0]
	if mappedApplicationRole.ID != realmApplicationRole.ID || mappedApplicationRole.Name != realmApplicationRole.Name || mappedApplicationRole.Description != realmApplicationRole.Description {
		t.Fatalf("Expected mapped group application role %+v to equal application group role %+v", mappedApplicationRole, realmApplicationRole)
	}
	// Remove role mapping for application
	err = client.RemoveGroupRoleMappings(testContext, addRoleMappingRequest)
	if err != nil {
		t.Fatalf("Error %s removing role mapping %+v to group %+v", err, addRoleMappingRequest, group)
	}
	// Verify application role mapping was removed
	groupRoleMapping, err = client.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	if val, ok := groupRoleMapping.ClientRoles[application.ID]; ok {
		t.Fatalf("Expected group %+v not to have role mappings %+v for application %+v", group, val, application)
	}
}

func TestRealmRoleCRD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)

	realmName := uniqueString("TestRealmRoleCRD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	autoGeneratedRealmRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	realmRoleName := "TestRoleFor " + realmName
	realmRoleCreateParams := CreateRealmRoleRequest{
		RealmName: realm.Name,
		Role: Role{
			Name:        realmRoleName,
			Description: "For test TestRealmRoleCRD",
		},
	}

	role, err := identityServiceClient.CreateRealmRole(testContext, realmRoleCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v role %+v using %+v", err, realm, realmRoleCreateParams, identityServiceClient)
	}

	describedRole, err := identityServiceClient.DescribeRealmRole(testContext, DescribeRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm %+v role %+v using %+v", err, realm, role, identityServiceClient)
	}

	if describedRole.Name != realmRoleCreateParams.Role.Name {
		t.Fatalf("expected described role %+v to have same name as it was created with %+v", describedRole, realmRoleCreateParams)
	}

	listedRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != 1+len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected only created role %+v to be listed, got %+v", role, listedRoles)
	}

	err = identityServiceClient.DeleteRealmRole(testContext, DeleteRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
	})

	if err != nil {
		t.Fatalf("error %s deleting realm %+v role %+v using %+v", err, realm, realmRoleCreateParams, identityServiceClient)
	}

	listedRoles, err = identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected deleted role %+v not to be listed, got %+v", role, listedRoles)
	}
}

func TestFetchApplicationSecret(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)

	realmName := uniqueString("TestFetchApplicationSecret")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	realmApplicationCreateParams := CreateRealmApplicationRequest{
		RealmName: realm.Name,
		Application: Application{
			ClientID: "jenkins-oidc-app",
			Name:     "Jenkins Your Build Is Ready",
			Active:   true,
			Protocol: ProtocolOIDC,
			OIDCSettings: ApplicationOIDCSettings{
				RootURL: "https://jenkins.acme.com",
			},
		},
	}
	application, err := identityServiceClient.CreateRealmApplication(testContext, realmApplicationCreateParams)
	if err != nil {
		t.Fatalf("error %s creating realm %+v application %+v using %+v", err, realm, realmApplicationCreateParams, identityServiceClient)
	}

	secret, err := identityServiceClient.FetchApplicationSecret(testContext, FetchApplicationSecretRequest{
		RealmName:     realm.Domain,
		ApplicationID: application.ID,
	})

	if err != nil {
		t.Fatalf("error %s fetching application %+v secret using %+v", err, application, identityServiceClient)
	}

	if secret.Secret == "" {
		t.Fatalf("expected OIDC configured application %+v secret to not be empty, got %+v", application, secret)
	}
}

func TestFetchApplicationSAMLSDescription(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)

	realmName := uniqueString("TestFetchApplicationSAMLSDescription")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	realmApplicationCreateParams := CreateRealmApplicationRequest{
		RealmName: realm.Name,
		Application: Application{
			ClientID: "aws-saml-app",
			Name:     "Jeff's Cloud",
			Active:   true,
			Protocol: ProtocolSAML,
			SAMLSettings: ApplicationSAMLSettings{
				DefaultEndpoint:                        "https://aws.com",
				IncludeAuthnStatement:                  true,
				IncludeOneTimeUseCondition:             false,
				SignDocuments:                          true,
				SignAssertions:                         true,
				ClientSignatureRequired:                true,
				ForcePostBinding:                       true,
				ForceNameIDFormat:                      false,
				NameIDFormat:                           "transient",
				IDPInitiatedSSOURLName:                 "amazon-aws",
				AssertionConsumerServicePOSTBindingURL: "https://signin.aws.amazon.com/saml",
			},
		},
	}
	application, err := identityServiceClient.CreateRealmApplication(testContext, realmApplicationCreateParams)
	if err != nil {
		t.Fatalf("error %s creating realm %+v application %+v using %+v", err, realm, realmApplicationCreateParams, identityServiceClient)
	}

	description, err := identityServiceClient.FetchApplicationSAMLDescription(testContext, FetchApplicationSAMLDescriptionRequest{
		RealmName:     realm.Domain,
		ApplicationID: application.ID,
		Format:        SAMLIdentityProviderDescriptionFormat,
	})

	if err != nil {
		t.Fatalf("error %s fetching application %+v secret using %+v", err, application, identityServiceClient)
	}

	if description.Description == "" {
		t.Fatalf("expected SAML configured application %+v description for format %s to not be empty, got %+v", application, SAMLIdentityProviderDescriptionFormat, description)
	}
}

func TestApplicationMapperCRD(t *testing.T) {
	// Create account and configure identity client
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	// Create realm
	realmName := uniqueString("TestApplicationMapperCRD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	// Ensure realm is cleaned up even if test fails
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Create realm OIDC application
	realmApplicationCreateParams := CreateRealmApplicationRequest{
		RealmName: realm.Domain,
		Application: Application{
			ClientID: "jenkins-oidc-app",
			Name:     "Jenkins Your Build Is Ready",
			Active:   true,
			Protocol: ProtocolOIDC,
			OIDCSettings: ApplicationOIDCSettings{
				RootURL: "https://jenkins.acme.com",
			},
		},
	}
	application, err := identityServiceClient.CreateRealmApplication(testContext, realmApplicationCreateParams)
	if err != nil {
		t.Fatalf("error %s creating realm %+v application %+v using %+v", err, realm, realmApplicationCreateParams, identityServiceClient)
	}
	// Retrieve the list of auto generated application mappers for later comparison
	listApplicationMapperRequest := ListRealmApplicationMappersRequest{
		RealmName:     realm.Domain,
		ApplicationID: application.ID,
	}
	autoGeneratedApplicationMappers, err := identityServiceClient.ListRealmApplicationMappers(testContext, listApplicationMapperRequest)
	if err != nil {
		t.Fatalf("error %s listing realm %+v application mappers using %+v", err, realm, identityServiceClient)
	}
	// Create an OIDC user attribute protocol mapper for the application
	realmApplicationMapperCreateParams := CreateRealmApplicationMapperRequest{
		RealmName:     realm.Domain,
		ApplicationID: application.ID,
		ApplicationMapper: ApplicationMapper{
			Name:             "Client Policy",
			Protocol:         ProtocolOIDC,
			MapperType:       UserAttributeOIDCApplicationMapperType,
			AddToUserInfo:    true,
			UserAttribute:    "policy",
			AddToIDToken:     true,
			AddToAccessToken: true,
			ClaimJSONType:    ClaimJSONStringType,
			TokenClaimName:   "policy",
		},
	}
	applicationMapper, err := identityServiceClient.CreateRealmApplicationMapper(testContext, realmApplicationMapperCreateParams)
	if err != nil {
		t.Fatalf("error %s creating realm %+v application mapper %+v using %+v", err, realm, realmApplicationMapperCreateParams, identityServiceClient)
	}
	// Verify described application parameter matches at least one parameter it was created with
	describedApplicationMapper, err := identityServiceClient.DescribeRealmApplicationMapper(testContext, DescribeRealmApplicationMapperRequest{
		RealmName:           realm.Domain,
		ApplicationID:       application.ID,
		ApplicationMapperID: applicationMapper.ID,
	})
	if err != nil {
		t.Fatalf("error %s describing realm %+v application mapper %+v using %+v", err, realm, applicationMapper, identityServiceClient)
	}
	if describedApplicationMapper.Name != realmApplicationMapperCreateParams.ApplicationMapper.Name {
		t.Fatalf("expected described application mapper %+v to have same name as it was created with %+v", describedApplicationMapper, realmApplicationMapperCreateParams)
	}
	// Verify created application mapper is present in list endpoint
	listedApplicationMappers, err := identityServiceClient.ListRealmApplicationMappers(testContext, listApplicationMapperRequest)
	if err != nil {
		t.Fatalf("error %s listing realm %+v application mappers using %+v", err, realm, identityServiceClient)
	}
	if len(listedApplicationMappers.ApplicationMappers) != 1+len(autoGeneratedApplicationMappers.ApplicationMappers) {
		t.Fatalf("expected only created application mapper %+v to be listed, got %+v", applicationMapper, listedApplicationMappers)
	}
	// Delete created application mapper
	err = identityServiceClient.DeleteRealmApplicationMapper(testContext, DeleteRealmApplicationMapperRequest{
		RealmName:           realm.Domain,
		ApplicationID:       application.ID,
		ApplicationMapperID: applicationMapper.ID,
	})
	if err != nil {
		t.Fatalf("error %s deleting realm %+v application mapper %+v using %+v", err, realm, realmApplicationMapperCreateParams, identityServiceClient)
	}
	// Verify deleted application mapper not present according to the server
	listedApplicationMappers, err = identityServiceClient.ListRealmApplicationMappers(testContext, listApplicationMapperRequest)
	if err != nil {
		t.Fatalf("error %s listing realm %+v application mappers using %+v", err, realm, identityServiceClient)
	}
	if len(listedApplicationMappers.ApplicationMappers) != len(autoGeneratedApplicationMappers.ApplicationMappers) {
		t.Fatalf("expected deleted application mapper %+v not to be listed, got %+v", applicationMapper, listedApplicationMappers)
	}
}

func TestSearchingIdentitiesWithEmailValidRealmReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	requestParam := SearchRealmIdentitiesRequest{
		RealmName:      realm.Name,
		IdentityEmails: []string{"katie@tozny.com"},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "Email" {
		t.Fatalf("Error Returning correct search criteria, Expected Email, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.RealmEmail == requestParam.IdentityEmails[0] {
			found = true
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityEmails, identities.SearchedIdentitiesInformation)
	}
}
func TestSearchingIdentitiesWithEmailValidRealmInvalidIdentitiesReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	requestParam := SearchRealmIdentitiesRequest{
		RealmName:      realm.Name,
		IdentityEmails: []string{"Luna@tozny.com"},
	}
	_, err = identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v should not error when searching invalid identities", err, requestParam)
	}
}

func TestSearchingIdentitiesOnlyReturnsIdentifiersForValidEmails(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}

	requestParam := SearchRealmIdentitiesRequest{
		RealmName:      realm.Name,
		IdentityEmails: []string{"katie@tozny.com", "Luna@tozny.com"},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "Email" {
		t.Fatalf("Error Returning correct search criteria, Expected Email, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.RealmEmail == requestParam.IdentityEmails[0] {
			found = true
		}
		if identity.RealmEmail == requestParam.IdentityEmails[1] {
			t.Fatalf("Error Returned Invalid Identity")
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityEmails, identities.SearchedIdentitiesInformation)
	}
}
func TestSearchingIdentitiesWithUsernameValidRealmReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	requestParam := SearchRealmIdentitiesRequest{
		RealmName:         realm.Name,
		IdentityUsernames: []string{"Katie"},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "Username" {
		t.Fatalf("Error Returning correct search criteria, Expected Username, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.RealmUsername == strings.ToLower(requestParam.IdentityUsernames[0]) {
			found = true
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityUsernames, identities.SearchedIdentitiesInformation)
	}
}

func TestSearchingIdentitiesWithUsernameValidRealmInvalidIdentitiesReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	requestParam := SearchRealmIdentitiesRequest{
		RealmName:         realm.Name,
		IdentityUsernames: []string{"Luna"},
	}
	_, err = identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
}
func TestSearchingIdentitiesOnlyReturnsIdentifiersForValidUsernames(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}

	requestParam := SearchRealmIdentitiesRequest{
		RealmName:         realm.Name,
		IdentityUsernames: []string{"katie", "luna"},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "Username" {
		t.Fatalf("Error Returning correct search criteria, Expected Username, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.RealmUsername == strings.ToLower(requestParam.IdentityUsernames[0]) {
			found = true
		}
		if identity.RealmUsername == strings.ToLower(requestParam.IdentityUsernames[1]) {
			t.Fatalf("Error Returned Invalid Identity")
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityUsernames, identities.SearchedIdentitiesInformation)
	}
}

func TestGetPrivateRealmInfoReturnsSuccessForAuthorizedRealmIdentity(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("PrivatRealmInfo")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	//defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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

	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	_, err = anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}

	realmInfo, err := identityServiceClient.PrivateRealmInfo(testContext, realmName)
	if err != nil {
		t.Fatalf("Error [%+v] Searching for Realm %+v", err, realmName)
	}
	if realmInfo.Name != realmName {
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
	if realmInfo.SecretsEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.SecretsEnabled)
	}
	if realmInfo.TozIDFederationEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.TozIDFederationEnabled)
	}
}

func TestSearchingIdentitiesOnlyReturnsIdentifiersForValidClientIDs(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	registerResponse, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}

	requestParam := SearchRealmIdentitiesRequest{
		RealmName:         realm.Name,
		IdentityClientIDs: []uuid.UUID{registerResponse.Identity.ToznyID, uuid.New()},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "ClientID" {
		t.Fatalf("Error Returning correct search criteria, Expected ClientIDs, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.ClientID == requestParam.IdentityClientIDs[0] {
			found = true
		}
		if identity.ClientID == requestParam.IdentityClientIDs[1] {
			t.Fatalf("Error Returned Invalid Identity")
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityClientIDs, identities.SearchedIdentitiesInformation)
	}
}

func TestSearchingIdentitiesWithClientIDsValidRealmReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestSearchIdentities")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
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
	registerParams := RegisterIdentityRequest{
		RealmRegistrationToken: registrationToken,
		RealmName:              realm.Name,
		Identity: Identity{
			Name:        identityName,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
			Email:       identityEmail,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	registerResponse, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("Error %s registering identity using %+v %+v", err, anonClient, registerParams)
	}
	requestParam := SearchRealmIdentitiesRequest{
		RealmName:         realm.Name,
		IdentityClientIDs: []uuid.UUID{registerResponse.Identity.ToznyID},
	}
	identities, err := identityServiceClient.SearchRealmIdentities(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error Searching for Realm %+v Identities %+v", err, requestParam)
	}
	// Valid identity should be returned
	if identities.SearchCriteria != "ClientID" {
		t.Fatalf("Error Returning correct search criteria, Expected ClientIds, Received %+v", identities.SearchCriteria)
	}
	var found bool
	for _, identity := range identities.SearchedIdentitiesInformation {
		if identity.ClientID == requestParam.IdentityClientIDs[0] {
			found = true
		}
	}
	if found != true {
		t.Fatalf("Error Returning correct Identities, Expected %+v, Received %+v", requestParam.IdentityClientIDs, identities.SearchedIdentitiesInformation)
	}
}

func TestUpdateRealmSetting(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("PrivatRealmInfo")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create Realm
	realm := createRealmWithParams(t, identityServiceClient, params)
	// defer delete
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Check Current Setttings
	realmInfo, err := identityServiceClient.PrivateRealmInfo(testContext, realmName)
	if err != nil {
		t.Fatalf("Error [%+v] Searching for Realm %+v", err, realmName)
	}
	if realmInfo.Name != realmName {
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
	if realmInfo.SecretsEnabled != false {
		t.Fatalf("Error Expected false , Received %+v", realmInfo.SecretsEnabled)
	}
	if realmInfo.TozIDFederationEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.TozIDFederationEnabled)
	}
	// Update Realm Setting
	// Not updating EmailLookUps which should be true!
	// Golang for empty bools default is false , so this should assure that doesnt happen
	secretsEnabled := true
	tozIDfederationEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MFAAvailable:           &([]string{"None"}),
		SecretsEnabled:         &(secretsEnabled),
		TozIDFederationEnabled: &(tozIDfederationEnabled),
	}

	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// Check current Settings
	realmInfo, err = identityServiceClient.PrivateRealmInfo(testContext, realmName)
	if err != nil {
		t.Fatalf("Error [%+v] Searching for Realm %+v", err, realmName)
	}
	if realmInfo.Name != realmName {
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
	if realmInfo.SecretsEnabled != true {
		t.Fatalf("Error Expected true, Received %+v %+v", realmInfo.SecretsEnabled, realmInfo)
	}
	if realmInfo.MFAAvailable[0] != "None" {
		t.Fatalf("Error Expected %+v, Received %+v", settingRequest.MFAAvailable, realmInfo)
	}

	if realmInfo.EmailLookupsEnabled != true {
		t.Fatalf("Error Expected true, Received %+v %+v", realmInfo.EmailLookupsEnabled, realmInfo)
	}
	if realmInfo.TozIDFederationEnabled != true {
		t.Fatalf("Error Expected true, Received %+v", realmInfo.TozIDFederationEnabled)
	}

}

func TestUpdateRealmSettingwithNoUpdatedValues(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("PrivatRealmInfo")
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	// Create Realm
	realm := createRealmWithParams(t, identityServiceClient, params)
	// defer delete
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Check Current Setttings
	realmInfo, err := identityServiceClient.PrivateRealmInfo(testContext, realmName)
	if err != nil {
		t.Fatalf("Error [%+v] Searching for Realm %+v", err, realmName)
	}
	if realmInfo.Name != realmName {
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
	if realmInfo.SecretsEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.SecretsEnabled)
	}
	if realmInfo.EmailLookupsEnabled != true {
		t.Fatalf("Error Expected true, Received %+v %+v", realmInfo.EmailLookupsEnabled, realmInfo)
	}
	if realmInfo.MFAAvailable[0] != "GoogleAuthenticator" {
		t.Fatalf("Error Expected Google Authenticator, Received %+v", realmInfo)
	}
	if realmInfo.TozIDFederationEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.TozIDFederationEnabled)
	}
	// Update Realm Setting with no new settings
	// resulting in no changes
	settingRequest := RealmSettingsUpdateRequest{}
	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// Check current Settings should be the same as above
	realmInfo, err = identityServiceClient.PrivateRealmInfo(testContext, realmName)
	if err != nil {
		t.Fatalf("Error [%+v] Searching for Realm %+v", err, realmName)
	}
	if realmInfo.Name != realmName {
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
	if realmInfo.SecretsEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.SecretsEnabled)
	}
	if realmInfo.EmailLookupsEnabled != true {
		t.Fatalf("Error Expected true, Received %+v %+v", realmInfo.EmailLookupsEnabled, realmInfo)
	}
	if realmInfo.MFAAvailable[0] != "GoogleAuthenticator" {
		t.Fatalf("Error Expected Google Authenticator, Received %+v", realmInfo)
	}
	if realmInfo.TozIDFederationEnabled != false {
		t.Fatalf("Error Expected false, Received %+v", realmInfo.TozIDFederationEnabled)
	}
}
func TestRealmRoleCRUD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestRealmRoleCRUD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	autoGeneratedRealmRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	realmRoleName := "TestRoleFor " + realmName
	realmRoleCreateParams := CreateRealmRoleRequest{
		RealmName: realm.Name,
		Role: Role{
			Name:        realmRoleName,
			Description: "TestRealmRoleCRUD",
		},
	}

	role, err := identityServiceClient.CreateRealmRole(testContext, realmRoleCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v role %+v using %+v", err, realm, realmRoleCreateParams, identityServiceClient)
	}

	describedRole, err := identityServiceClient.DescribeRealmRole(testContext, DescribeRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
	})

	if err != nil {
		t.Fatalf("error %s describing realm %+v role %+v using %+v", err, realm, role, identityServiceClient)
	}

	if describedRole.Name != realmRoleCreateParams.Role.Name {
		t.Fatalf("expected described role %+v to have same name as it was created with %+v", describedRole, realmRoleCreateParams)
	}

	listedRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != 1+len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected only created role %+v to be listed, got %+v", role, listedRoles)
	}

	updatedRole, err := identityServiceClient.UpdateRealmRole(testContext, UpdateRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
		Role: Role{
			Name:        realmRoleName,
			Description: "Updated Description",
		},
	})

	if err != nil {
		t.Fatalf("error %s updating realm %+v role %+v using %+v", err, realm, role, identityServiceClient)
	}

	if updatedRole.Name != realmRoleCreateParams.Role.Name {
		t.Fatalf("expected updated role %+v to have same name as it was created with %+v", updatedRole, realmRoleCreateParams)
	}
	if updatedRole.Description == realmRoleCreateParams.Role.Description {
		t.Fatalf("expected updated role %+v to have different name as it was created with %+v", updatedRole, realmRoleCreateParams)
	}
	if updatedRole.Description != "Updated Description" {
		t.Fatalf("expected updated role %+v description to be Updated Description ", updatedRole)
	}

	listedRoles, err = identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != 1+len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected only created role %+v to be listed, got %+v", role, listedRoles)
	}
	err = identityServiceClient.DeleteRealmRole(testContext, DeleteRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
	})

	if err != nil {
		t.Fatalf("error %s deleting realm %+v role %+v using %+v", err, realm, realmRoleCreateParams, identityServiceClient)
	}

	listedRoles, err = identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected deleted role %+v not to be listed, got %+v", role, listedRoles)
	}
}
func TestUpdateRole(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}

	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)

	realmName := uniqueString("TestRealmRoleCRUD")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	autoGeneratedRealmRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	realmRoleName := "TestRoleFor " + realmName
	realmRoleCreateParams := CreateRealmRoleRequest{
		RealmName: realm.Name,
		Role: Role{
			Name:        realmRoleName,
			Description: "TestRealmRoleCRUD",
		},
	}

	role, err := identityServiceClient.CreateRealmRole(testContext, realmRoleCreateParams)

	if err != nil {
		t.Fatalf("error %s creating realm %+v role %+v using %+v", err, realm, realmRoleCreateParams, identityServiceClient)
	}

	updatedRole, err := identityServiceClient.UpdateRealmRole(testContext, UpdateRealmRoleRequest{
		RealmName: realm.Name,
		RoleID:    role.ID,
		Role: Role{
			Name:        realmRoleName,
			Description: "Updated Description",
		},
	})

	if err != nil {
		t.Fatalf("error %s updating realm %+v role %+v using %+v", err, realm, role, identityServiceClient)
	}

	if updatedRole.Name != realmRoleCreateParams.Role.Name {
		t.Fatalf("expected updated role %+v to have same name as it was created with %+v", updatedRole, realmRoleCreateParams)
	}
	if updatedRole.Description == realmRoleCreateParams.Role.Description {
		t.Fatalf("expected updated role %+v to have different name as it was created with %+v", updatedRole, realmRoleCreateParams)
	}
	if updatedRole.Description != "Updated Description" {
		t.Fatalf("expected updated role %+v description to be Updated Description ", updatedRole)
	}

	listedRoles, err := identityServiceClient.ListRealmRoles(testContext, realm.Name)

	if err != nil {
		t.Fatalf("error %s listing realm %+v roles using %+v", err, realm, identityServiceClient)
	}

	if len(listedRoles.Roles) != 1+len(autoGeneratedRealmRoles.Roles) {
		t.Fatalf("expected only created role %+v to be listed, got %+v", role, listedRoles)
	}
}

func TestUpdateGroup(t *testing.T) {
	// test setup
	client := createIdentityServiceClient(t)
	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	groupName := uniqueString("realm group")
	group := createRealmGroup(t, client, realm.Name, groupName)
	defer client.DeleteRealmGroup(testContext, DeleteRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})

	// test execution
	updatedGroupName := uniqueString("realm group update")
	updatedAttributes := map[string][]string{
		"key1": {"value1"},
		"key2": {"value2"},
	}
	params := UpdateRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
		Group: Group{
			Name:       updatedGroupName,
			Attributes: updatedAttributes,
		},
	}

	group, err := client.UpdateRealmGroup(testContext, params)
	if err != nil {
		t.Fatalf("error updating realm group %+v: %+v", params, err)
	}

	// test assertion
	actual, err := client.DescribeRealmGroup(testContext, DescribeRealmGroupRequest{
		RealmName: realm.Name,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("error %s describing realm group %s using %+v", err, group.ID, client)
	}

	if len(actual.ID) == 0 {
		t.Errorf("expected result to have ID")
	}
	if actual.Name != updatedGroupName {
		t.Errorf("expected result group name to be '%s', was '%s'", updatedGroupName, actual.Name)
	}
	if _, ok := actual.Attributes["key1"]; !ok {
		t.Errorf("expected result group attributes to include '%s', was '%s'", "key1", actual.Attributes)
	}
	if _, ok := actual.Attributes["key2"]; !ok {
		t.Errorf("expected result group attributes to include '%s', was '%s'", "key2", actual.Attributes)
	}
}

func TestInitiateIdentityLoginSucceedsWhenUnlocked(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := uniqueString("TestInitiateIdentityLoginSucceedsWhenUnlocked")

	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	identityName := "Freud"
	identityEmail := "test-emails-group+freud@tozny.com"
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
	queenClientInfo.Host = toznyCyclopsHost
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
			Email:       identityEmail,
			PublicKeys:  map[string]string{e3dbClients.DefaultEncryptionKeyType: encryptionKeyPair.Public.Material},
			SigningKeys: map[string]string{signingKeys.Public.Type: signingKeys.Public.Material},
			FirstName:   identityFirstName,
			LastName:    identityLastName,
		},
	}
	anonConfig := e3dbClients.ClientConfig{
		Host: toznyCyclopsHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(testContext, registerParams)
	if err != nil {
		t.Fatalf("RegisterIdentity Error: %+v\n", err)
	}
	initiateLoginParams := IdentityLoginRequest{
		Username:   identity.Identity.Name,
		RealmName:  realm.Name,
		AppName:    "account",
		LoginStyle: "api",
	}
	_, err = identityServiceClient.InitiateIdentityLogin(testContext, initiateLoginParams)
	// Expect a 401 error when the Challenge is requested from storage service because this internal request
	// does not have the cyclops based authentication headers that the endpoint expects.
	// This failure happens AFTER checking the account is unlocked.
	var tozError *e3dbClients.RequestError
	if errors.As(err, &tozError) {
		if tozError.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Expected 401 error %s requesting a challenge from storage service", err)
		}
	} else {

		t.Fatalf("Expected 401 error %s requesting a challenge from storage service", err)
	}
}

func TestCreateAccessRequest(t *testing.T) {
	// INITIAL SETUP
	client, registrationToken := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)
	identityResponse, identityServiceClient := registerIdentity(t, client, realm.Name, registrationToken)
	// Update Realm Setting
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err := client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}

	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list realm roles %s", err)
	}
	if len(autoGeneratedRealmRoles.Roles) == 0 {
		t.Fatal("Need roles for this test :(")
	}
	role := autoGeneratedRealmRoles.Roles[0]
	accessPolicy := AccessPolicy{
		RequiredApprovals:            1,
		MaximumAccessDurationSeconds: 5000,
		ApprovalRoles:                []Role{role},
	}
	groupAccessPolicies := GroupAccessPolicies{
		GroupID:        group.ID,
		AccessPolicies: []AccessPolicy{accessPolicy},
	}
	accessPolicyParams := UpsertAccessPolicyRequest{
		RealmName:           realmName,
		GroupAccessPolicies: groupAccessPolicies,
	}
	_, err = client.UpsertAccessPolicies(testContext, accessPolicyParams)
	if err != nil {
		t.Fatalf("Error: [%s] while creating new access policy", err)
	}

	reason := "SAY! I LIKE GREEN EGGS AND HAM!"
	ttl := 1000
	request := CreateAccessRequestRequest{
		Groups:                []AccessRequestGroup{{ID: group.ID}},
		Reason:                reason,
		RealmName:             realmName,
		AccessDurationSeconds: ttl,
	}

	// ACT
	response, err := identityServiceClient.CreateAccessRequest(testContext, request)

	// ASSERT
	if err != nil {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}

	if response.ID <= 0 {
		t.Fatalf("ID should greater than zero new AccessRequest: %+v", response)
	}

	if response.Reason != reason {
		t.Fatalf("Reason should be [%s] but was [%s]", reason, response.Reason)
	}

	if response.AccessDurationSeconds != ttl {
		t.Fatalf("AccessDurationSeconds should be [%d] but was [%d]", ttl, response.AccessDurationSeconds)
	}

	if response.State != AccessRequestOpenState {
		t.Fatalf("State should be [%s] but was [%s]", AccessRequestOpenState, response.State)
	}
	if len(response.Groups) != 1 {
		t.Fatalf("Expected Group to be included in response %+v  Response %+v", group, response)
	}
	if response.Groups[0].Name != group.Name {
		t.Fatalf("Expected Group name to be %+v Recieved %+v", group.Name, response.Groups[0].Name)
	}
	if response.Groups[0].ID != group.ID {
		t.Fatalf("Expected Group ID to be %+v Recieved %+v", group.ID, response.Groups[0].ID)
	}
	if response.RequestorDetails.Username != identityResponse.Identity.Name {
		t.Fatalf("Expected Username to Match Requestor Username instead Got %+v, Expected %+v", response.RequestorDetails.Username, identityResponse.Identity.Name)
	}
}

func TestReadCreatedAccessRequest(t *testing.T) {
	// INITIAL SETUP
	client, registrationToken := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)
	_, identityServiceClient := registerIdentity(t, client, realm.Name, registrationToken)
	// Update Realm Setting
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err := client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list realm roles %s", err)
	}
	if len(autoGeneratedRealmRoles.Roles) == 0 {
		t.Fatal("Need roles for this test :(")
	}
	role := autoGeneratedRealmRoles.Roles[0]
	accessPolicy := AccessPolicy{
		RequiredApprovals:            1,
		MaximumAccessDurationSeconds: 5000,
		ApprovalRoles:                []Role{role},
	}
	groupAccessPolicies := GroupAccessPolicies{
		GroupID:        group.ID,
		AccessPolicies: []AccessPolicy{accessPolicy},
	}
	accessPolicyParams := UpsertAccessPolicyRequest{
		RealmName:           realmName,
		GroupAccessPolicies: groupAccessPolicies,
	}
	_, err = client.UpsertAccessPolicies(testContext, accessPolicyParams)
	if err != nil {
		t.Fatalf("Error: [%s] while creating new access policy", err)
	}

	reason := "SAY! I LIKE GREEN EGGS AND HAM!" + uuid.New().String()
	ttl := 1000
	request := CreateAccessRequestRequest{
		Groups:                []AccessRequestGroup{{ID: group.ID}},
		Reason:                reason,
		RealmName:             realmName,
		AccessDurationSeconds: ttl,
	}
	createdAccessRequest, err := identityServiceClient.CreateAccessRequest(testContext, request)
	if err != nil {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}
	describeAccessRequsetParams := DescribeAccessRequestRequest{
		AccessRequestID: createdAccessRequest.ID,
	}

	// ACT
	describedAccessRequest, err := identityServiceClient.DescribeAccessRequest(testContext, describeAccessRequsetParams)

	// ASSERT
	if err != nil {
		t.Fatalf("Error %s attempting to describe created access request %+v using params %+v access request", err, createdAccessRequest, describeAccessRequsetParams)
	}

	if describedAccessRequest.Reason != reason {
		t.Fatalf("Expected described created access request reaoson to equal %s, got %+v", reason, describedAccessRequest)
	}
}

func TestReadDeletedAccessRequestReturns404(t *testing.T) {
	// INITIAL SETUP
	client, registrationToken := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)
	_, identityServiceClient := registerIdentity(t, client, realm.Name, registrationToken)
	// Update Realm Setting
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err := client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list realm roles %s", err)
	}
	if len(autoGeneratedRealmRoles.Roles) == 0 {
		t.Fatal("Need roles for this test :(")
	}
	role := autoGeneratedRealmRoles.Roles[0]
	accessPolicy := AccessPolicy{
		RequiredApprovals:            1,
		MaximumAccessDurationSeconds: 5000,
		ApprovalRoles:                []Role{role},
	}
	groupAccessPolicies := GroupAccessPolicies{
		GroupID:        group.ID,
		AccessPolicies: []AccessPolicy{accessPolicy},
	}
	accessPolicyParams := UpsertAccessPolicyRequest{
		RealmName:           realmName,
		GroupAccessPolicies: groupAccessPolicies,
	}
	_, err = client.UpsertAccessPolicies(testContext, accessPolicyParams)
	if err != nil {
		t.Fatalf("Error: [%s] while creating new access policy", err)
	}

	reason := "SAY! I LIKE GREEN EGGS AND HAM!" + uuid.New().String()
	ttl := 1000
	request := CreateAccessRequestRequest{
		Groups:                []AccessRequestGroup{{ID: group.ID}},
		Reason:                reason,
		RealmName:             realmName,
		AccessDurationSeconds: ttl,
	}
	createdAccessRequest, err := identityServiceClient.CreateAccessRequest(testContext, request)
	if err != nil {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}
	deleteAccessRequsetParams := DeleteAccessRequestRequest{
		AccessRequestID: createdAccessRequest.ID,
	}
	err = identityServiceClient.DeleteAccessRequest(testContext, deleteAccessRequsetParams)
	if err != nil {
		t.Fatalf("Error %s deleting access request [%+v]", err, deleteAccessRequsetParams)
	}
	// ACT
	describeAccessRequsetParams := deleteAccessRequsetParams
	_, err = identityServiceClient.DescribeAccessRequest(testContext, describeAccessRequsetParams)

	// ASSERT
	if err == nil {
		t.Fatalf("Expected error reading deleted access request %+v", describeAccessRequsetParams)
	}
	tozError, ok := err.(*e3dbClients.RequestError)
	if !ok {
		t.Fatalf("Expected tozny request error but got %+v", err)

	}
	if tozError.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 error reading deleted access request but got %+v", tozError)
	}
}

func TestSearchForAllSelfCreatedAccessRequests(t *testing.T) {
	// INITIAL SETUP
	client, registrationToken := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)
	_, identityServiceClient := registerIdentity(t, client, realm.Name, registrationToken)
	// Update Realm Setting
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err := client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list realm roles %s", err)
	}
	if len(autoGeneratedRealmRoles.Roles) == 0 {
		t.Fatal("Need roles for this test :(")
	}
	role := autoGeneratedRealmRoles.Roles[0]
	accessPolicy := AccessPolicy{
		RequiredApprovals:            1,
		MaximumAccessDurationSeconds: 5000,
		ApprovalRoles:                []Role{role},
	}
	groupAccessPolicies := GroupAccessPolicies{
		GroupID:        group.ID,
		AccessPolicies: []AccessPolicy{accessPolicy},
	}
	accessPolicyParams := UpsertAccessPolicyRequest{
		RealmName:           realmName,
		GroupAccessPolicies: groupAccessPolicies,
	}
	_, err = client.UpsertAccessPolicies(testContext, accessPolicyParams)
	if err != nil {
		t.Fatalf("Error: [%s] while creating new access policy", err)
	}

	reason := "SAY! I LIKE GREEN EGGS AND HAM!" + uuid.New().String()
	ttl := 1000
	request := CreateAccessRequestRequest{
		Groups:                []AccessRequestGroup{{ID: group.ID}},
		Reason:                reason,
		RealmName:             realmName,
		AccessDurationSeconds: ttl,
	}
	firstCreatedAccessRequest, err := identityServiceClient.CreateAccessRequest(testContext, request)
	if err != nil {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}
	secondCreatedAccessRequest, err := identityServiceClient.CreateAccessRequest(testContext, request)
	if err != nil {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}

	// ACT
	accessRequestSearchParams := AccessRequestSearchRequest{
		AccessRequestSearchFilters: AccessRequestSearchFilters{
			RequestorIDs: []string{identityServiceClient.ClientID},
		},
	}
	searchResponse, err := identityServiceClient.SearchAccessRequests(testContext, accessRequestSearchParams)
	// ASSERT
	if err != nil {
		t.Fatalf("Error %s attempting to search for created access request using params %+v", err, accessRequestSearchParams)
	}
	expectedAccessRequestIDs := []int64{firstCreatedAccessRequest.ID, secondCreatedAccessRequest.ID}
	for _, expectedAccessRequestID := range expectedAccessRequestIDs {
		var found bool
		for _, accessRequest := range searchResponse.AccessRequests {
			if accessRequest.ID == expectedAccessRequestID {
				if accessRequest.Groups[0].Name != group.Name {
					t.Fatalf("Expected Group name to be %+v Got %+v", group.Name, accessRequest.Groups[0].Name)
					break
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Expected to find created access request %d in search response %+v", expectedAccessRequestID, searchResponse.AccessRequests)
		}
	}
}

func TestInitiateFederationConnectionForAuthorizedRealmReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := fmt.Sprintf("FederationConnect%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Update Realm Setting
	tozIDFederationEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		TozIDFederationEnabled: &(tozIDFederationEnabled),
	}

	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}

	requestParam := InitializeFederationConnectionRequest{
		RealmName:        realm.Name,
		FederationSource: "tozid",
	}
	response, err := identityServiceClient.InitiateFederationConnection(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error [%+v] Initiating Federation Connection for Realm %+v", err, requestParam)
	}
	if response.RealmName != realmName {
		t.Fatalf("Error Expected %+v, Recieved %+v", realmName, response.RealmName)
	}
	if response.ConnectionID == uuid.Nil {
		t.Fatalf("Error Expected a valid UUID, Recieved %+v", response.ConnectionID)
	}
	if response.APICredential == "" {
		t.Fatalf("Error Expected a credential, Recieved %+v", response.APICredential)
	}
}

func TestUpsertAccessRequestPolicy(t *testing.T) {
	// INITIAL SETUP
	client, _ := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)

	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list default realm roles %s", err)
	}
	upsertAccessPoliciesParam := UpsertAccessPolicyRequest{
		RealmName: realmName,
		GroupAccessPolicies: GroupAccessPolicies{
			GroupID: group.ID,
			AccessPolicies: []AccessPolicy{
				{
					ApprovalRoles: []Role{
						autoGeneratedRealmRoles.Roles[0],
					},
					RequiredApprovals:            1,
					MaximumAccessDurationSeconds: 1000,
				},
			},
		},
	}
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err = client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	// ACT
	response, err := client.UpsertAccessPolicies(testContext, upsertAccessPoliciesParam)

	// ASSERT
	if err != nil {
		t.Fatalf("Error %s upserting access request policies %+v", err, upsertAccessPoliciesParam)
	}

	if len(response.GroupAccessPolicies.AccessPolicies) != 1 {
		t.Fatalf("Error creating access request [%+v] (realm: %+v)", err, realmName)
	}
}

func TestListCreatedAccessRequestPolicy(t *testing.T) {
	// INITIAL SETUP
	client, _ := createIdentityServiceClientAndToken(t)
	realm := createRealm(t, client)
	realmName := realm.Name
	defer client.DeleteRealm(testContext, realm.Name)

	// ARRANGE
	groupName := uuid.New().String()
	group := createRealmGroup(t, client, realmName, groupName)
	autoGeneratedRealmRoles, err := client.ListRealmRoles(testContext, realmName)
	if err != nil {
		t.Fatalf("Failed to list default realm roles %s", err)
	}
	mpcEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		MPCEnabled: &(mpcEnabled),
	}

	err = client.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}
	upsertAccessPoliciesParam := UpsertAccessPolicyRequest{
		RealmName: realmName,
		GroupAccessPolicies: GroupAccessPolicies{
			GroupID: group.ID,
			AccessPolicies: []AccessPolicy{
				{
					ApprovalRoles: []Role{
						autoGeneratedRealmRoles.Roles[0],
					},
					RequiredApprovals:            1,
					MaximumAccessDurationSeconds: 1000,
				},
			},
		},
	}
	response, err := client.UpsertAccessPolicies(testContext, upsertAccessPoliciesParam)
	if err != nil {
		t.Fatalf("Error %s upserting access request policies %+v", err, upsertAccessPoliciesParam)
	}
	if len(response.GroupAccessPolicies.AccessPolicies) != 1 {
		t.Fatalf("Expected only one  group access request policy [%+v] got %+v)", response.GroupAccessPolicies.AccessPolicies, upsertAccessPoliciesParam)
	}

	listAccessPoliciesRequest := ListAccessPoliciesRequest{
		RealmName: realmName,
		GroupIDs:  []string{group.ID},
	}

	// ACT
	listResponse, err := client.ListAccessPolicies(testContext, listAccessPoliciesRequest)
	// ASSERT
	if err != nil {
		t.Fatalf("Error %s listing access request policies for realm %+s", err, realmName)
	}

	var found bool
	for _, listedAccessPolicies := range listResponse.GroupAccessPolicies {
		for _, accessPolicy := range listedAccessPolicies.AccessPolicies {
			if accessPolicy.ID == response.GroupAccessPolicies.AccessPolicies[0].ID {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("Expected to find created access request policy %+v when listing access request policies for realm %+v", response, listResponse)

	}

}

func TestGetFederatedIdentitiesForSyncWithDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestSyncASingleFederatedIdentityWithDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register Identity with Realm
	identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)

	// Get the UserID of the Identity
	id, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, identity.Identity.Name)
	if err != nil {
		t.Fatalf("error %s caused by describing identity", err)
	}

	usernames := []string{id.Name}

	// No pagination necessary
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		IncludeDetails:       true,
		Credentials:          credentials,
		Usernames:            usernames,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}
	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	if len(syncResponse.FederatedIdentities) != 1 {
		t.Fatalf("Expected one Identity, got %+v", len(syncResponse.FederatedIdentities))
	}
	if syncResponse.FederatedIdentities[0].Username != usernames[0] {
		t.Fatalf("Expected User ID %+v, but received %+v", usernames[0], syncResponse.FederatedIdentities[0].Username)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

}

func TestSyncSomeFederatedIdentitiesWithDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	numberOfIdentities := 10
	var names []string
	for i := 0; i < numberOfIdentities; i++ {
		registerIdentity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)
		identity, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, registerIdentity.Identity.Name)
		if err != nil {
			t.Fatalf("Error %s while describing Identity %s for Realm %s", err, registerIdentity.Identity.Name, realm.Name)
		}
		names = append(names, identity.Name)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	var usernames []string = names[0:4]
	reqParams := GetFederatedIdentitiesForSyncRequest{ // No pagination necessary
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       true,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	foundIdentities := len(syncResponse.FederatedIdentities)
	if foundIdentities != len(usernames) {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

}

func TestSyncAllFederatedIdentitiesWithNoDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       false,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestSyncSomeFederatedIdentitiesWithNoDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error
	// Create and register many Identities with the Realm
	numberOfIdentities := 10
	var names []string
	for i := 0; i < numberOfIdentities; i++ {
		registerIdentity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)
		identity, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, registerIdentity.Identity.Name)
		if err != nil {
			t.Fatalf("Error %s while describing Identity %s for Realm %s", err, registerIdentity.Identity.Name, realm.Name)
		}
		names = append(names, identity.Name)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	var usernames []string = names[0:4]
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       false,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	foundIdentities := len(syncResponse.FederatedIdentities)
	if foundIdentities != len(usernames) {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestSyncASingleFederatedIdentityWithNoDetails(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register Identity with Realm
	identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)

	// Get the UserID of the Identity
	id, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, identity.Identity.Name)
	if err != nil {
		t.Fatalf("error %s caused by describing identity", err)
	}

	usernames := []string{id.Name}
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       false,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	if len(syncResponse.FederatedIdentities) != 1 {
		t.Fatalf("Expected one Identity, got %+v", len(syncResponse.FederatedIdentities))
	}
	if syncResponse.FederatedIdentities[0].Username != id.Name {
		t.Fatalf("Expected User ID %+v, but received %+v", id.Name, syncResponse.FederatedIdentities[0].Username)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestGetFederatedIdentitiesForSyncMultiplePagesOfIdentities(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 10
	perPage := 5
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestGetFederatedIdentitiesForSyncGetsRolesGroupsAndGroupRoleMappings(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Add Groups, Roles, and Group Role Mappings
	groupName := uniqueString("TestGetFederatedIdentitiesForSyncGetsRolesGroupsAndGroupRoleMappings Group")
	group := createRealmGroup(t, identityServiceClient, realm.Name, groupName)

	// Createe Realm Application
	application := createRealmApplication(t, identityServiceClient, realm.Name)

	// Create a Role for the Application
	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, identityServiceClient, realm.Name, application.ID, roleName)
	groupRoleMapping, err := identityServiceClient.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	// Verify it doesn't have any assigned
	// role mappings for the application yet
	if val, ok := groupRoleMapping.ClientRoles[application.ID]; ok {
		t.Fatalf("Expected group %+v not to have role mappings %+v for application %+v", group, val, application)
	}

	// Add role mapping for application
	addRoleMappingRequest := AddGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
		RoleMapping: RoleMapping{
			ClientRoles: map[string][]Role{
				application.ID: []Role{
					*realmApplicationRole,
				},
			},
		},
	}

	err = identityServiceClient.AddGroupRoleMappings(testContext, addRoleMappingRequest)
	if err != nil {
		t.Fatalf("Error %s adding role mapping %+v to group %+v", err, addRoleMappingRequest, group)
	}
	// Verify application role mapping was added
	groupRoleMapping, err = identityServiceClient.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	applicationRoleMappings, ok := groupRoleMapping.ClientRoles[application.ID]
	if !ok {
		t.Fatalf("Expected group %+v to have role mappings %+v for application %+v", group, groupRoleMapping, application)
	}
	mappedApplicationRole := applicationRoleMappings[0]
	if mappedApplicationRole.ID != realmApplicationRole.ID || mappedApplicationRole.Name != realmApplicationRole.Name || mappedApplicationRole.Description != realmApplicationRole.Description {
		t.Fatalf("Expected mapped group application role %+v to equal application group role %+v", mappedApplicationRole, realmApplicationRole)
	}

	// Make Identities
	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		identityResponse := createIdentityAndRegisterWithRealm(t, realm, registrationToken)
		groupID := []string{group.ID}
		updateGroupMembership(t, identityServiceClient, "update", realm.Name, identityResponse.Identity.ToznyID.String(), groupID)
	}

	// Call GetFederatedIdentitiesForSync handler
	var totalIdentities []DetailedFederatedIdentity
	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	// Confirm we receive the Groups, Roles, and Group Role Mappings of an Identity
	identity := totalIdentities[0]
	if identity.Group[0].ID != group.ID {
		t.Fatalf("Expected synced Identity to have the same group")
	}

	identityApplicationRoleMappings, ok := identity.GroupRoleMappings[0].ClientRoles[application.ID]
	if !ok {
		t.Fatalf("Expected Identity %+v to have role mappings %+v for application %+v", identity, identity.GroupRoleMappings[0], application)
	}
	mappedApplicationRoleForIdentity := identityApplicationRoleMappings[0]
	if mappedApplicationRoleForIdentity.ID != realmApplicationRole.ID || mappedApplicationRoleForIdentity.Name != realmApplicationRole.Name || mappedApplicationRoleForIdentity.Description != realmApplicationRole.Description {
		t.Fatalf("Expected Identity %+v to have mapped group application role  %+v to equal application group role %+v", identity, mappedApplicationRole, realmApplicationRole)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestGetFederatedIdentitiesForSyncLimitSetToOneNoRepeatsOrSkips(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	var createdIdentities []*RegisterIdentityResponse
	for i := 0; i < numberOfIdentities; i++ {
		identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)
		createdIdentities = append(createdIdentities, identity)
	}

	first := 0
	max := 1
	for first != -1 {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                max, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken

		// Avoids the case in which next token is -1, so synced Identities is 0
		if first != 0 {
			if len(syncResponse.FederatedIdentities) != max {
				t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, max, len(syncResponse.FederatedIdentities))
			}
		}

		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)

		if first == 0 {
			first = -1
		}
	}

	if first != -1 {
		t.Fatalf("Expected next token to be -1, but received %d", first)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

	// Verify that we received every Identity and that there were no repeats
	for _, i := range createdIdentities {
		if !syncContainsIdentity(totalIdentities, i.Identity.Name) {
			t.Fatalf("Expected sync to contain Identity %+v", i)
		}
	}
}

func TestGetFederatedIdentitiesForSyncLimitSetToTwoNoRepeatsOrSkips(t *testing.T) {
	// Setup
	realm, identityServiceClient, registrationToken, credentials := ConfigureAndCreateAFederatedRealm(t)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	var createdIdentities []*RegisterIdentityResponse
	for i := 0; i < numberOfIdentities; i++ {
		identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken)
		createdIdentities = append(createdIdentities, identity)
	}

	first := 0
	max := 2
	for first != -1 {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                max, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken

		// Avoids the case in which next token is -1, so synced Identities is 0
		if first != 0 {
			if len(syncResponse.FederatedIdentities) != max {
				t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, max, len(syncResponse.FederatedIdentities))
			}
		}

		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)

		if first == 0 {
			first = -1
		}
	}

	if first != -1 {
		t.Fatalf("Expected next token to be -1, but received %d", first)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

	// Verify that we received every Identity and that there were no repeats
	for _, i := range createdIdentities {
		if !syncContainsIdentity(totalIdentities, i.Identity.Name) {
			t.Fatalf("Expected sync to contain Identity %+v", i)
		}
	}
}
