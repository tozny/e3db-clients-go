package keycloakClient

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tozny/utils-go"
)

var (
	cyclopsServiceHost           = utils.MustGetenv("TOZNY_CYCLOPS_SERVICE_HOST")
	HTTPTimeout                  = 10 * time.Second
	keycloakMasterRealm          = utils.MustGetenv("KEYCLOAK_MASTER_REALM")
	keycloakUsername             = utils.MustGetenv("KEYCLOAK_USERNAME")
	keycloakPassword             = utils.MustGetenv("KEYCLOAK_PASSWORD")
	accessTokenLifespan          = int32(utils.MustGetenvInt("IDENTITY_ACCESS_TOKEN_LIFESPAN"))
	ssoSessionIdleTimeout        = int32(utils.MustGetenvInt("DEFAULT_IDENTITY_SSO_SESSION_IDLE_TIMEOUT"))
	ssoSessionMaxLifespan        = int32(utils.MustGetenvInt("DEFAULT_IDENTITY_SSO_SESSION_MAX_LIFESPAN"))
	revokeRefreshToken           = utils.MustGetenv("DEFAULT_IDENTITY_REVOKE_REFRESH_TOKEN")
	refreshTokenMaxReuse         = int32(utils.MustGetenvInt("DEFAULT_IDENTITY_REFRESH_TOKEN_MAX_REUSE"))
	toggleClientEnableListenerID = "Tozny User Enabled Listener"
	toznyEventLogger             = "Tozny Event Logger"
	jbossLoggingID               = "jboss-logging"
	registrationToken            = utils.MustGetenv("REGISTRATION_TOKEN")
)

func CreateRealm(kcClient *Client, adminToken string, realmName string) error {

	// call the post method
	active := true
	defaultRealmTheme := "tozny"
	displayName := "testing"
	displayNameHTML := fmt.Sprintf("<div class=\"kc-logo-text\"><span>%v</span></div>", displayName)
	eventsListeners := []string{toggleClientEnableListenerID, jbossLoggingID, toznyEventLogger}
	attributes := map[string]interface{}{"registrationToken": registrationToken}
	truePointer := true
	revokeRefresh, err := strconv.ParseBool(revokeRefreshToken)
	if err != nil {
		return err
	}
	createRealmParams := RealmRepresentation{
		Realm:                     &realmName,
		Enabled:                   &active,
		AdminTheme:                &defaultRealmTheme,
		AccountTheme:              &defaultRealmTheme,
		DisplayName:               &displayName,
		DisplayNameHtml:           &displayNameHTML,
		LoginTheme:                &defaultRealmTheme,
		EventsListeners:           &eventsListeners,
		AdminEventsDetailsEnabled: &truePointer,
		Attributes:                &attributes,
		SSOSessionIdleTimeout:     &ssoSessionIdleTimeout,
		SSOSessionMaxLifespan:     &ssoSessionMaxLifespan,
		RefreshTokenMaxReuse:      &refreshTokenMaxReuse,
		RevokeRefreshToken:        &revokeRefresh,
		AccessTokenLifespan:       &accessTokenLifespan,
	}
	if err != nil {
		return err
	}

	_, err = kcClient.CreateRealm(adminToken, createRealmParams)

	if err != nil {
		return err
	}

	return nil
}

func DeleteIdentityProvider(kcClient *Client, adminToken string, realmName string, alias string) error {

	err := kcClient.DeleteIdentityProvider(adminToken, realmName, alias)
	if err != nil {
		return err
	}
	return nil
}

// Verifies that calling getToken with the master realm succeeds
func TestGetTokenSucceedsWithValidClientCredentials(t *testing.T) {
	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}
	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}
	token, err := kcClient.GetToken(keycloakMasterRealm, keycloakUsername, keycloakPassword)
	if err != nil {
		t.Fatalf("Get token failed with err: %+v", err)
	}
	if token == "" {
		t.Fatal("Token must be nonempty.")
	}
}

func TestCreateRealmSucceeds(t *testing.T) {
	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}
	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}
	token, err := kcClient.GetToken(keycloakMasterRealm, keycloakUsername, keycloakPassword)
	if err != nil {
		t.Fatalf("Get token failed with err: %+v", err)
	}
	// call the post method
	realmName := "testing" + uuid.New().String()
	active := true
	defaultRealmTheme := "tozny"
	displayName := "testing"
	displayNameHTML := fmt.Sprintf("<div class=\"kc-logo-text\"><span>%v</span></div>", displayName)
	eventsListeners := []string{toggleClientEnableListenerID, jbossLoggingID, toznyEventLogger}
	attributes := map[string]interface{}{"registrationToken": registrationToken}
	truePointer := true
	revokeRefresh, err := strconv.ParseBool(revokeRefreshToken)
	if err != nil {
		t.Fatalf("parsing revoke refresh token failed: err %+v", err)
	}
	createRealmParams := RealmRepresentation{
		Realm:                     &realmName,
		Enabled:                   &active,
		AdminTheme:                &defaultRealmTheme,
		AccountTheme:              &defaultRealmTheme,
		DisplayName:               &displayName,
		DisplayNameHtml:           &displayNameHTML,
		LoginTheme:                &defaultRealmTheme,
		EventsListeners:           &eventsListeners,
		AdminEventsDetailsEnabled: &truePointer,
		Attributes:                &attributes,
		SSOSessionIdleTimeout:     &ssoSessionIdleTimeout,
		SSOSessionMaxLifespan:     &ssoSessionMaxLifespan,
		RefreshTokenMaxReuse:      &refreshTokenMaxReuse,
		RevokeRefreshToken:        &revokeRefresh,
		AccessTokenLifespan:       &accessTokenLifespan,
	}
	if err != nil {
		t.Fatalf("Could not open plugin from realmRootPath. Err: %+v", err)
	}

	_, err = kcClient.CreateRealm(token, createRealmParams)
	if err != nil {
		t.Fatalf("Create realm failed with err: %+v", err)
	}
}

func TestCreateRealmSucceedsFailsWithFakeToken(t *testing.T) {
	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}
	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}
	token := "this-is-my-fake-token-that-is-very-fake"

	// call the post method
	realmName := "testing" + uuid.New().String()
	active := true
	defaultRealmTheme := "tozny"
	displayName := "testing"
	displayNameHTML := fmt.Sprintf("<div class=\"kc-logo-text\"><span>%v</span></div>", displayName)
	eventsListeners := []string{toggleClientEnableListenerID, jbossLoggingID, toznyEventLogger}
	attributes := map[string]interface{}{"registrationToken": registrationToken}
	truePointer := true
	revokeRefresh, err := strconv.ParseBool(revokeRefreshToken)
	if err != nil {
		t.Fatalf("parsing revoke refresh token failed: err %+v", err)
	}
	createRealmParams := RealmRepresentation{
		Realm:                     &realmName,
		Enabled:                   &active,
		AdminTheme:                &defaultRealmTheme,
		AccountTheme:              &defaultRealmTheme,
		DisplayName:               &displayName,
		DisplayNameHtml:           &displayNameHTML,
		LoginTheme:                &defaultRealmTheme,
		EventsListeners:           &eventsListeners,
		AdminEventsDetailsEnabled: &truePointer,
		Attributes:                &attributes,
		SSOSessionIdleTimeout:     &ssoSessionIdleTimeout,
		SSOSessionMaxLifespan:     &ssoSessionMaxLifespan,
		RefreshTokenMaxReuse:      &refreshTokenMaxReuse,
		RevokeRefreshToken:        &revokeRefresh,
		AccessTokenLifespan:       &accessTokenLifespan,
	}
	if err != nil {
		t.Fatalf("Could not open plugin from realmRootPath. Err: %+v", err)
	}

	_, err = kcClient.CreateRealm(token, createRealmParams)
	if err == nil {
		t.Fatalf("Expected Error %s Creating a realm with a fake token", err)
	}
}

func TestCreateDeleteIdentityProvider(t *testing.T) {

	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}

	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}

	token, err := kcClient.GetToken(keycloakMasterRealm, keycloakUsername, keycloakPassword)
	if err != nil {
		t.Fatalf("Get token failed with err: %+v", err)
	}
	randomId := uuid.New().String()
	realmName := "realm-" + randomId
	err = CreateRealm(kcClient, token, realmName)

	if err != nil {
		t.Fatalf("Error %+v while creating realm", err)
	}

	providerConfig := map[string]interface{}{
		"authorizationUrl": "https://example.com/auth",
		"tokenUrl":         "https://example.com/token",
		"clientAuthMethod": "client_secret_post",
		"clientId":         randomId,
		"clientSecret":     randomId,
	}

	alias := "idp-" + randomId
	displayName := "IdP " + randomId
	enabled := true
	providerId := "oidc"

	createProviderParams := IdentityProviderRequestRepresentation{
		ProviderId:  providerId,
		Alias:       alias,
		Config:      providerConfig,
		DisplayName: displayName,
		Enabled:     enabled,
	}
	_, err = kcClient.CreateIdentityProvider(token, realmName, createProviderParams)
	if err != nil {
		t.Fatalf("Error %+v while creating identity provider", err)
	}

	err = DeleteIdentityProvider(kcClient, token, realmName, alias)

	if err != nil {
		t.Fatalf("Error %+v while deleting identity provider", err)
	}
}

/*
func TestGetIdentityProviderMappers(t *testing.T) {

	keycloakClientConfig := Config{
		AddrTokenProvider: cyclopsServiceHost,
		AddrAPI:           cyclopsServiceHost,
		Timeout:           HTTPTimeout,
	}
	kcClient, err := New(keycloakClientConfig)
	if err != nil {
		t.Fatalf("Failure creating keycloak client with err: %+v", err)
	}
	token, err := kcClient.GetToken(keycloakMasterRealm, keycloakUsername, keycloakPassword)
	if err != nil {
		t.Fatalf("Get token failed with err: %+v", err)
	}
	realmName := "localtest"
	alias := "azure-ad"
	response, err := kcClient.GetIdentityProviderMappers(token, realmName, alias)
	if err != nil {
		t.Fatalf("Error %+v while creating identity provider", err)
	}
	t.Fatalf("Response : %+v", response)
}
*/
