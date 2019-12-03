package identityClient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/utils-go/server"
)

const (
	identityServiceBasePath = "/v1/identity" // HTTP PATH prefix for calls to the Identity service
	realmResourceName       = "realm"
	realmLoginPathPrefix    = "/auth/realms"
	realmLoginPathPostfix   = "/protocol/openid-connect/token"
)

var (
	internalIdentityServiceBasePath = fmt.Sprintf("/internal%s", identityServiceBasePath)
)

// E3dbIdentityClient implements an http client for communication with an e3db Identity service.
type E3dbIdentityClient struct {
	Host        string
	SigningKeys e3dbClients.SigningKeys
	ClientID    string
	httpClient  *http.Client
}

// ListOIDCKeysForRealm returns a list of all configured keys for OIDC flows for a given realm and error (if any)
func (c *E3dbIdentityClient) ListOIDCKeysForRealm(ctx context.Context, realmName string) (ListRealmOIDCKeysResponse, error) {
	var listedKeys ListRealmOIDCKeysResponse
	path := fmt.Sprintf("%s%s/%s/protocol/openid-connect/certs", c.Host, realmLoginPathPrefix, realmName)
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return listedKeys, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &listedKeys)
	if err != nil {
		return listedKeys, err
	}
	return listedKeys, err
}

// BrokerIdentityChallange begins a broker-based login flow using the specified params, returning error (if any).
func (c *E3dbIdentityClient) BrokerIdentityChallenge(ctx context.Context, params BrokerChallengeRequest) error {
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/broker/%s/%s/challenge", realmResourceName, params.RealmName)
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return err
	}
	return e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
}

// RegisterIdentity completes a broker based login flow by giving the broker the needed authentication
// information returning the recovery note and error (if any).
func (c *E3dbIdentityClient) BrokerIdentityLogin(ctx context.Context, params BrokerLoginRequest) (*BrokerLoginResponse, error) {
	var identity *BrokerLoginResponse
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/broker/%s/%s/login", realmResourceName, params.RealmName)
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

// RegisterRealmBrokerIdentity creates and associates an Identity to be used
// to backup the credentials for the realm's Identities, returning the created identity and error (if any).
func (c *E3dbIdentityClient) RegisterRealmBrokerIdentity(ctx context.Context, params RegisterRealmBrokerIdentityRequest) (*RegisterRealmBrokerIdentityResponse, error) {
	var identity *RegisterRealmBrokerIdentityResponse
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/%s/%s/broker/identity", realmResourceName, params.RealmName)
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identity)
	return identity, err
}

// IdentityLogin logs in the client identity to the specified realm,
// returning the identities realm authentication info and error (if any).
func (c *E3dbIdentityClient) IdentityLogin(ctx context.Context, realmName string) (*IdentityLoginResponse, error) {
	var identity *IdentityLoginResponse
	path := c.Host + realmLoginPathPrefix + fmt.Sprintf("/%s", realmName) + realmLoginPathPostfix
	data := url.Values{}
	// All login requests are authenticated as valid tsv1 signed requests,
	// set these for compatibility with default Keycloak Oauth direct grant request handling.
	data.Set("grant_type", "password")
	// Not the actual realm admin, just an identity with API level access.
	data.Set("client_id", "admin-cli")
	request, err := http.NewRequest("POST", path, strings.NewReader(data.Encode()))
	if err != nil {
		return identity, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identity)
	return identity, err
}

// InternalIdentityLogin requests internal authentication context
// for the ability of the authenticated identity to login into the specified realm
// returning the identities internal realm authentication context and error (if any).
func (c *E3dbIdentityClient) InternalIdentityLogin(ctx context.Context, params InternalIdentityLoginRequest) (*InternalIdentityLoginResponse, error) {
	var identity *InternalIdentityLoginResponse
	path := c.Host + internalIdentityServiceBasePath + fmt.Sprintf("/%s/%s", realmResourceName, params.RealmName) + "/login"
	request, err := e3dbClients.CreateRequest("POST", path, nil)
	if err != nil {
		return identity, err
	}
	request.Header.Set(server.ToznyAuthNHeader, params.XToznyAuthNHeader)
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

func (c *E3dbIdentityClient) InternalUpdateIdentityActiveByKeycloakUserID(ctx context.Context, keyCloakUserID string, active bool) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/user/" + keyCloakUserID + "/active"
	body := InternalUpdateActiveForKeycloakUserID{
		Active: active,
	}
	request, err := e3dbClients.CreateRequest("PUT", path, &body)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

// RegisterIdentity registers an identity with the specified realm using the specified parameters,
// returning the created identity and error (if any).
func (c *E3dbIdentityClient) RegisterIdentity(ctx context.Context, params RegisterIdentityRequest) (*RegisterIdentityResponse, error) {
	var identity *RegisterIdentityResponse
	path := c.Host + identityServiceBasePath + "/register"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

// ListRealms lists the realms belonging to the requester returning the realms and error (if any).
func (c *E3dbIdentityClient) ListRealms(ctx context.Context) (*ListRealmsResponse, error) {
	var realms *ListRealmsResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return realms, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realms)
	return realms, err
}

// DeleteRealm deletes the realm with the specified name, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealm(ctx context.Context, realmName string) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + fmt.Sprintf("/%s", realmName)
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealm describes the realm with the specified name, returning the realm and error (if any).
func (c *E3dbIdentityClient) DescribeRealm(ctx context.Context, realmName string) (*Realm, error) {
	var realm *Realm
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + fmt.Sprintf("/%s", realmName)
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return realm, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realm)
	return realm, err
}

// CreateRealm creates a realm using the specified parameters,
// returning the created realm (including it's associated sovereign) and error (if any).
func (c *E3dbIdentityClient) CreateRealm(ctx context.Context, params CreateRealmRequest) (*Realm, error) {
	var realm *Realm
	path := c.Host + identityServiceBasePath + "/" + realmResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return realm, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realm)
	return realm, err
}

// ServiceCheck checks whether the identity service is up and working.
// returning error if unable to connect service
func (c *E3dbIdentityClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
	return err
}

// HealthCheck checks whether the identity service is up,
// returning error if unable to connect to the service.
func (c *E3dbIdentityClient) HealthCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/healthcheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
	return err
}

// New returns a new E3dbHookClient configured with the provided values
func New(config e3dbClients.ClientConfig) E3dbIdentityClient {
	return E3dbIdentityClient{
		Host:        config.Host,
		SigningKeys: config.SigningKeys,
		ClientID:    config.ClientID,
		httpClient:  &http.Client{},
	}
}
