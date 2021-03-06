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
	internalToznyCyclopsHost                  = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	internalIdentityServiceHost               = os.Getenv("E3DB_IDENTITY_SERVICE_HOST")
	internalE3dbAuthHost                      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	internalE3dbAccountHost                   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	internalE3dbAPIKey                        = os.Getenv("E3DB_API_KEY_ID")
	internalE3dbAPISecret                     = os.Getenv("E3DB_API_KEY_SECRET")
	internalE3dbClientID                      = os.Getenv("E3DB_CLIENT_ID")
	InternalInternalBootstrapPublicSigningKey = os.Getenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	InternalBootstrapPrivateSigningKey        = os.Getenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	InternalValidAccountClientConfig          = e3dbClients.ClientConfig{
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbAccountHost,
		AuthNHost: internalE3dbAuthHost,
	}
	internalE3dbIdentityHost         = internalToznyCyclopsHost
	InternalBootIdentityClientConfig = e3dbClients.ClientConfig{
		ClientID:  internalE3dbClientID,
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbIdentityHost,
		AuthNHost: internalE3dbAuthHost,
		SigningKeys: e3dbClients.SigningKeys{
			Public: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalInternalBootstrapPublicSigningKey,
			},
			Private: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalBootstrapPrivateSigningKey,
			},
		},
	}
	internalTestContext          = context.TODO()
	internalAccountServiceClient = accountClient.New(InternalValidAccountClientConfig)
	InternalBootstrapClient      = New(InternalBootIdentityClientConfig)
)

func internalUniqueString(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().Unix())
}
func TestInternalIdentityLoginWithAuthenticatedRealmIdentity(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &internalAccountServiceClient, accountTag, internalE3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = internalE3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := internalUniqueString("TestInternalIdentityLoginWithAuthenticatedRealmIdentity")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(internalTestContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(internalTestContext, realm.Name)
	identityName := "Freud"
	signingKeys, err := e3dbClients.GenerateSigningKeys()
	if err != nil {
		t.Fatalf("error %s generating identity signing keys", err)
	}
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Fatalf("error %s generating encryption keys", err)
	}
	queenClientInfo.Host = internalE3dbAccountHost
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
		Host: internalE3dbIdentityHost,
	}
	anonClient := New(anonConfig)
	identity, err := anonClient.RegisterIdentity(internalTestContext, registerParams)
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
	internalIdentityAuthenticationContext, err := registeredIdentityClient.InternalIdentityLogin(internalTestContext, internalIdentityLoginParams)
	if err != nil {
		t.Fatalf("error %s retrieving internal registered identity %+v using  %+v", err, identity.Identity, registeredIdentityClient)
	}
	if internalIdentityAuthenticationContext.RealmID != realm.ID || internalIdentityAuthenticationContext.RealmName != realm.Domain || internalIdentityAuthenticationContext.Active != true {
		t.Fatalf("expected registered identity %+v to be an active member of realm %+v , got  %+v", identity.Identity, realm, internalIdentityAuthenticationContext)
	}
}

func TestInternalLDAPCacheCRUD(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &internalAccountServiceClient, accountTag, internalE3dbAuthHost)
	if err != nil {
		t.Fatalf("Error %q making new account", err)
	}
	queenClientInfo.Host = internalE3dbIdentityHost
	identityServiceClient := New(queenClientInfo)
	realmName := internalUniqueString("TestInternalLDAPCrud")
	sovereignName := "Yassqueen"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm, err := identityServiceClient.CreateRealm(internalTestContext, params)
	if err != nil {
		t.Fatalf("%s realm creation %+v failed using %+v", err, params, identityServiceClient)
	}
	defer identityServiceClient.DeleteRealm(internalTestContext, realm.Name)
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
	err = InternalBootstrapClient.InternalSetLDAPCache(internalTestContext, realmName, expectedLDAPData)
	if err != nil {
		t.Fatalf("%v setting LDAP cache in %q realm with data %+v", err, realmName, expectedLDAPData)
	}
	// Fetch LDAP test data
	fetchedData, err := InternalBootstrapClient.InternalLDAPCache(internalTestContext, realmName, expectedLDAPData.ID)
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
	err = InternalBootstrapClient.InternalDeleteLDAPCache(internalTestContext, realmName, expectedLDAPData.ID)
	if err != nil {
		t.Fatalf("%+v when trying to remove LDAP cache for user %q", err, expectedLDAPData.ID)
	}
}
