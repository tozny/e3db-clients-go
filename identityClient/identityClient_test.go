package identityClient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
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
	bootstrapClient                = New(BootIdentityClientConfig)
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
	identityEmail := "freud@example.com"
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
	if internalIdentityAuthenticationContext.RealmID != realm.ID || internalIdentityAuthenticationContext.RealmName != realm.Domain || internalIdentityAuthenticationContext.Active != true {
		t.Fatalf("expected registered identity %+v to be an active member of realm %+v , got  %+v", identity.Identity, realm, internalIdentityAuthenticationContext)
	}
}

func TestInternalLDAPCacheCRUD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %q making new account", err)
	}
	queenClientInfo.Host = e3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := "TestInternalLDAPCrud"
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
	// Set up test LDAP data
	expectedLDAPData := LDAPCache{
		ID:               uuid.New().String(),
		LDAPID:           uuid.New().String(),
		DN:               "cn=users,dn=tozny,dn=test",
		RdnAttributeName: "cn",
		Classes:          []string{"test", "of", "classes"},
		Attributes: map[string][]string{
			"cn":       {"testuser"},
			"multi":    {"multiple", "values"},
			"editable": {"this is editable"},
		},
		ReadOnlyAttributes: []string{"multi"},
		Groups:             []string{"group1", "group2"},
		Roles:              []string{"role1", "role2", "role3"},
	}
	err = bootstrapClient.InternalSetLDAPCache(testContext, realmName, expectedLDAPData)
	if err != nil {
		t.Fatalf("%v setting LDAP cache in %q realm with data %+v", err, realmName, expectedLDAPData)
	}
	// Fetch LDAP test data
	fetchedData, err := bootstrapClient.InternalLDAPCache(testContext, realmName, expectedLDAPData.ID)
	if err != nil {
		t.Fatalf("%v getting LDAP cache in %q realm for ID %q", err, realmName, expectedLDAPData.ID)
	}
	// Validate response
	if fetchedData.ID != expectedLDAPData.ID {
		t.Errorf("User ID in LDAP cache doesn't match -- expected %q received %q", expectedLDAPData.ID, fetchedData.ID)
	}
	if fetchedData.LDAPID != expectedLDAPData.LDAPID {
		t.Errorf("User LDAP ID in LDAP cache doesn't match -- expected %q received %q", expectedLDAPData.LDAPID, fetchedData.LDAPID)
	}
	if fetchedData.DN != expectedLDAPData.DN {
		t.Errorf("User LDAP DN in LDAP cache doesn't match -- expected %q received %q", expectedLDAPData.DN, fetchedData.DN)
	}
	if fetchedData.RdnAttributeName != expectedLDAPData.RdnAttributeName {
		t.Errorf("User RdnAttributename in LDAP cache doesn't match -- expected %q received %q", expectedLDAPData.RdnAttributeName, fetchedData.RdnAttributeName)
	}
	if len(fetchedData.Classes) != len(expectedLDAPData.Classes) {
		t.Errorf("Length of user LDAP classes did not match -- expected %d received %d", len(expectedLDAPData.Classes), len(fetchedData.Classes))
	}
	for c := range fetchedData.Classes {
		found := false
		for f := range expectedLDAPData.Classes {
			if c == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing class in class list of user LDAP classes -- looked for %q in %+v", c, expectedLDAPData.Classes)
		}
	}
	if len(fetchedData.Groups) != len(expectedLDAPData.Groups) {
		t.Errorf("Length of user LDAP groups did not match -- expected %d received %d", len(expectedLDAPData.Groups), len(fetchedData.Groups))
	}
	for c := range fetchedData.Groups {
		found := false
		for f := range expectedLDAPData.Groups {
			if c == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing group in group list of user LDAP groups -- looked for %q in %+v", c, expectedLDAPData.Groups)
		}
	}
	if len(fetchedData.Roles) != len(expectedLDAPData.Roles) {
		t.Errorf("Length of user LDAP roles did not match -- expected %d received %d", len(expectedLDAPData.Roles), len(fetchedData.Roles))
	}
	for c := range fetchedData.Roles {
		found := false
		for f := range expectedLDAPData.Roles {
			if c == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing role in role list of user LDAP roles -- looked for %q in %+v", c, expectedLDAPData.Roles)
		}
	}
	if len(fetchedData.ReadOnlyAttributes) != len(expectedLDAPData.ReadOnlyAttributes) {
		t.Errorf("Length of user LDAP read only attributes did not match -- expected %d received %d", len(expectedLDAPData.ReadOnlyAttributes), len(fetchedData.ReadOnlyAttributes))
	}
	for c := range fetchedData.ReadOnlyAttributes {
		found := false
		for f := range expectedLDAPData.ReadOnlyAttributes {
			if c == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing read only attribute in list of user LDAP read only attributes -- looked for %q in %+v", c, expectedLDAPData.ReadOnlyAttributes)
		}
	}
	if len(fetchedData.Attributes) != len(expectedLDAPData.Attributes) {
		t.Errorf("Length of user LDAP attributes did not match -- expected %d received %d", len(expectedLDAPData.Attributes), len(fetchedData.Attributes))
	}
	for name, attrs := range fetchedData.Attributes {
		expectedAttrs, ok := expectedLDAPData.Attributes[name]
		if !ok {
			t.Errorf("missing expected attribute %q in fetch attributes %+v", name, expectedLDAPData.Attributes)
		}
		if len(expectedAttrs) != len(attrs) {
			t.Errorf("Length of attribute list %q did not match -- expected %d received %d", name, len(expectedAttrs), len(attrs))
		}
		for c := range attrs {
			found := false
			for f := range expectedAttrs {
				if c == f {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Missing item in attribute list %q of user LDAP read only attributes -- looked for %q in %+v", name, c, expectedAttrs)
			}
		}
	}
	// Clear the cache
	err = bootstrapClient.InternalDeleteLDAPCache(testContext, realmName, expectedLDAPData.ID)
	if err != nil {
		t.Fatalf("%+v when trying to remove LDAP cache for user %q", err, expectedLDAPData.ID)
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

	realmName := fmt.Sprintf("TestApplicationCRD%d", time.Now().Unix())

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

	realmName := fmt.Sprintf("TestProviderCRD%d", time.Now().Unix())

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

	realmName := fmt.Sprintf("TestProviderMapperCRD%d", time.Now().Unix())

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
	realmName := fmt.Sprintf("TestListIdentities%d", time.Now().Unix())
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
		identityEmail := fmt.Sprintf("testListID+%d@example.com", i)
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
	realmName := fmt.Sprintf("TestListIdentities%d", time.Now().Unix())
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
		identityEmail := fmt.Sprintf("testListID+%d@example.com", i)
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
	realmName := fmt.Sprintf("TestListIdentities%d", time.Now().Unix())
	sovereignName := "yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
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

func registerIdentity(t *testing.T, identityServiceClient E3dbIdentityClient, realmName string, registrationToken string) *RegisterIdentityResponse {
	identityTag := uuid.New().String()
	identityName := "Freud" + identityTag
	identityEmail := "freud+" + identityTag + "@example.com"
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
	return identity
}

func uniqueString(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().Unix())
}

func createRealm(t *testing.T, identityServiceClient E3dbIdentityClient) *Realm {
	unique := uniqueString("realm")
	params := CreateRealmRequest{
		RealmName:     unique,
		SovereignName: "realmsovereign",
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
	return realm
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

func TestDeleteIdentityRemoves(t *testing.T) {
	client, registrationToken := createIdentityServiceClientAndToken(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	identity := registerIdentity(t, client, realm.Name, registrationToken)
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

	roleDescription := (roleName + " description")

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
	roleDescription := (roleName + " description")
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

	realmName := fmt.Sprintf("TestRealmRoleCRD%d", time.Now().Unix())
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

	realmName := fmt.Sprintf("TestFetchApplicationSecret%d", time.Now().Unix())
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

	realmName := fmt.Sprintf("TestFetchApplicationSAMLSDescription%d", time.Now().Unix())
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
	realmName := fmt.Sprintf("TestApplicationMapperCRD%d", time.Now().Unix())
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("TestSearchIdentities%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
	realmName := fmt.Sprintf("PrivatRealmInfo%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(testContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v\n", err, params, identityServiceClient)
	}
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
		t.Fatalf("Error Expected %+v, Received %+v", realmName, realmInfo.Name)
	}
}
