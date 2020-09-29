package identityClient

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	if internalIdentityAuthenticationContext.RealmID != realm.ID || internalIdentityAuthenticationContext.RealmName != realm.Name || internalIdentityAuthenticationContext.Active != true {
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
			"cn":       []string{"testuser"},
			"multi":    []string{"multiple", "values"},
			"editable": []string{"this is editable"},
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
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
	})

	actual, err := client.DescribeRealmApplicationRole(testContext, DescribeRealmApplicationRoleRequest{
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
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

func TestListApplicationRoleReturnsNoApplicationRolesWhenApplicationHasNone(t *testing.T) {
	client := createIdentityServiceClient(t)

	realm := createRealm(t, client)
	defer client.DeleteRealm(testContext, realm.Name)
	application := createRealmApplication(t, client, realm.Name)
	defer client.DeleteRealmApplication(testContext, DeleteRealmApplicationRequest{
		RealmName:     realm.Name,
		ApplicationID: application.ID,
	})

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)

	if len(actual) != 0 {
		t.Errorf("expected 0 application roles before creating one")
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

	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	defer client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
	})

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)

	if len(actual) != 1 {
		t.Errorf("expected result to have one element")
	}

	role := actual[0]

	if role.Name != roleName {
		t.Errorf("expected result role name to be '%s', was '%s'", roleName, role.Name)
	}

	roleDescription := (roleName + " description")

	if role.Description != roleDescription {
		t.Errorf("expected result role description to be '%s', was '%s'", roleDescription, role.Description)
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
	realmApplicationRole := createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	err := client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
	})

	if err != nil {
		t.Errorf("expected no error deleting realm application role, got: %+v", err)
	}

	actual, err := client.DescribeRealmApplicationRole(testContext, DescribeRealmApplicationRoleRequest{
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
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

	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, client, realm.Name, application.ID, roleName)
	err := client.DeleteRealmApplicationRole(testContext, DeleteRealmApplicationRoleRequest{
		RealmName:         realm.Name,
		ApplicationID:     application.ID,
		ApplicationRoleID: realmApplicationRole.ID,
	})

	if err != nil {
		t.Errorf("expected no error deleting realm application role, got: %+v", err)
	}

	actual := listRealmApplicationRoles(t, client, realm.Name, application.ID)

	if len(actual) != 0 {
		t.Errorf("expected 0 application roles after deleting the one created")
	}
}
