package keycloakClient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/gbrlsnchs/jwt/v2"
	"github.com/gorilla/schema"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"gopkg.in/h2non/gentleman.v2"
	"gopkg.in/h2non/gentleman.v2/plugins/timeout"
)

const (
	realmRootPath                                = "/auth/admin/realms"
	userExtensionPath                            = "/auth/realms"
	clientResourceName                           = "clients"
	roleResourceName                             = "roles"
	roleByIDResourceName                         = "roles-by-id"
	groupResourceName                            = "groups"
	groupSingleResourceName                      = "group"
	roleMappingResourceName                      = "role-mappings"
	realmResourceName                            = "realm"
	adminResourceName                            = "admin"
	userResourceName                             = "users"
	defaultGroupResourceName                     = "default-groups"
	clientSecretResourceName                     = "client-secret"
	protocolMapperResourceName                   = "protocol-mappers"
	modelsResourceName                           = "models"
	protocolResourceName                         = "protocol"
	optionalClientScopeResourceName              = "optional-client-scopes"
	defaultClientScopeResourceName               = "default-client-scopes"
	defaultResourceName                          = "default"
	componentsResourceName                       = "components"
	UserFederationProviderType                   = "org.keycloak.storage.UserStorageProvider"
	authenticationResourceName                   = "authentication"
	logoutResourceName                           = "logout"
	initiateLoginPath                            = "/auth/realms/%s/protocol/openid-connect/auth"
	UserSessionNoteOIDCApplicationMapperType     = "oidc-usersessionmodel-note-mapper"
	UserAttributeOIDCApplicationMapperType       = "oidc-usermodel-attribute-mapper"
	GroupMembershipOIDCApplicationMapperType     = "oidc-group-membership-mapper"
	RoleListSAMLApplicationMapperType            = "saml-role-list-mapper"
	UserPropertySAMLApplicationMapperType        = "saml-user-property-mapper"
	UserFederationProviderLDAPMapperType         = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	UserModelRealmRoleOIDCApplicationMapperType  = "oidc-usermodel-realm-role-mapper"
	UserModelClientRoleOIDCApplicationMapperType = "oidc-usermodel-client-role-mapper"
	UserModelAttributeOIDCApplicationMapperType  = "oidc-usermodel-attribute-mapper"
	resourceServerResourceName                   = "resource-server"
	authzResourceName                            = "authz"
	resourceResourceName                         = "resource"
	policyResourceName                           = "policy"
	realmsResourceName                           = "realms"
	staticResourceName                           = "static"
	permissionResourceName                       = "permission"
	mfaResourceName                              = "mfa"
	toznyInternalGroupPolicyName                 = "__ToznyInternalGroupPolicy"
	toznyInternalDenyPolicyName                  = "__ToznyInternalDenyPolicy"
	toznyInternalUserPolicyName                  = "__ToznyInternalUserPolicy"
	toznyInternalAuthzMap                        = "__ToznyInternalAuthzMap"
	toznyInternalAuthzResource                   = "__ToznyInternalAuthz"
)

var (
	RefreshExhaustedError = errors.New("refresh token exhausted")
	SessionExpiredError   = errors.New("auth session expired")
	// KeycloakTokenInfoLock allows for access control so only one routine is able to access the Keycloak Token Info
	KeycloakTokenInfoLock = &sync.Mutex{}
	encoder               = schema.NewEncoder()
)

// New returns a keycloak client
func New(config Config) (*Client, error) {
	urlToken, err := url.Parse(config.AddrTokenProvider)
	if err != nil {
		return nil, fmt.Errorf("Could not parse Token Provider URL\n err: %+v", err)
	}
	urlApi, err := url.Parse(config.AddrAPI)
	if err != nil {
		return nil, fmt.Errorf("Could not parse API URL\n err: %+v", err)
	}
	httpClient := http.Client{
		Timeout: config.Timeout,
	}
	client := Client{
		tokenProviderURL:                 urlToken,
		apiURL:                           urlApi,
		httpClient:                       &httpClient,
		tokens:                           map[tokenMapKey]*TokenInfo{},
		refreshAuthTokenBeforeExpiration: config.RefreshAuthTokenBeforeExpiration,
		config:                           config,
	}
	// Check if logging is enabled, if it is, pass in logger
	if config.EnabledLogging {
		loggingClient := e3dbClients.LoggingClient{
			StandardClient:   httpClient,
			StructuredLogger: config.Logger,
		}
		client.httpClient = &loggingClient.StandardClient
	}
	return &client, nil
}

// tokenAutoRefresher returns a token refresher func that will automatically refresh the token
// before the given expiration time
func (c *Client) tokenAutoRefresher(expires time.Time, realm string, username string, password string, onFailure func(error)) *time.Timer {
	// Refresh before the auth token expires
	nextRefresh := expires.Sub(time.Now().Add(time.Duration(c.refreshAuthTokenBeforeExpiration) * time.Second))
	refresher := time.AfterFunc(nextRefresh, func(realm, username, password string, onFailure func(error), c *Client) func() {
		// send back a function which will re-call this method after the timeout
		// capturing the arguments in a closure.
		return func() {
			c.AutoRefreshToken(realm, username, password, onFailure)
		}
	}(realm, username, password, onFailure, c))
	return refresher
}

// AutoRefreshToken starts a process where an access token is kept perpetually
// warm in the cache, refreshing itself five seconds before it expires.
func (c *Client) AutoRefreshToken(realm string, username string, password string, onFailure func(error)) {
	info, err := c.GetTokenInfo(realm, username, password, true)
	if err != nil {
		// Unable to fetch the token, allow userland to determine the correct
		// behavior here -- retry, panic, log, etc...
		onFailure(err)
		return
	}
	info.autorefreshes = true
	info.onRefreshFailure = onFailure
	// Pass in arguments to allow original args to get garbage collected.
	info.refresher = c.tokenAutoRefresher(info.Expires, username, username, password, onFailure)
}

// toTokenJson translated the expiration info in a tokenJSON to a full token with time.Time
// values. The issued at (iat) value must be when the token was issued or expiration values
// will be incorrect.
func (t *tokenJSON) toTokenInfo(iat time.Time) *TokenInfo {
	token := TokenInfo{
		TokenType:    t.TokenType,
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}
	token.Expires = iat.Add(time.Duration(t.ExpiresIn) * time.Second)
	token.RefreshExpires = iat.Add(time.Duration(t.RefreshExpiresIn) * time.Second)
	return &token
}

// GetTokenInfo fetches token info from the cache or from the server, refreshing as necessary by either starting
// a new session or using the refresh token to extend the current session.
func (c *Client) GetTokenInfo(realm string, username string, password string, force bool) (*TokenInfo, error) {
	var newTokenInfo *TokenInfo
	var err error
	key := tokenMapKey{
		realm:    realm,
		username: username,
	}

	// Get exclusive access to the token
	KeycloakTokenInfoLock.Lock()
	defer KeycloakTokenInfoLock.Unlock()

	tokenInfo, exists := c.tokens[key]
	if !exists || time.Now().After(tokenInfo.RefreshExpires) {
		// If the token doesn't exist or can no longer be refreshed, get a new token
		newTokenInfo, err = c.FetchToken(realm, username, password)
		if err != nil {
			// remove the key from the list of tokens
			delete(c.tokens, key)
			return nil, err
		}
	} else if force || time.Now().After(tokenInfo.Expires) {
		// If the token if expired or a force refresh is requested, attempt to refresh the token
		newTokenInfo, err = c.RefreshToken(realm, tokenInfo.RefreshToken)
		if err != nil {
			// if the session has expired or the token can't be refreshed, attempt to get a new token
			if err == RefreshExhaustedError || err == SessionExpiredError {
				newTokenInfo, err = c.FetchToken(realm, username, password)
			}
			if err != nil {
				delete(c.tokens, key)
				return nil, err
			}
		}
	}
	// If a new token was fetched, reset the state using this token
	if newTokenInfo != nil {
		if exists && tokenInfo.refresher != nil {
			tokenInfo.refresher.Stop()
		}
		if exists && tokenInfo.autorefreshes {
			newTokenInfo.refresher = c.tokenAutoRefresher(newTokenInfo.Expires, realm, username, password, tokenInfo.onRefreshFailure)
		}

		c.tokens[key] = newTokenInfo
		tokenInfo = newTokenInfo
	}
	return tokenInfo, nil
}

// GetToken returns a valid token from the cache or from keycloak as needed.
func (c *Client) GetToken(realm string, username string, password string) (string, error) {
	tokenInfo, err := c.GetTokenInfo(realm, username, password, false)
	if err != nil {
		return "", err
	}
	return tokenInfo.AccessToken, nil
}

// FetchToken fetches a valid token from keycloak.
func (c *Client) FetchToken(realm string, username string, password string) (*TokenInfo, error) {
	bodyString := fmt.Sprintf("username=%s&password=%s&grant_type=password&client_id=admin-cli", username, password)
	return c.doTokenRequest(realm, bodyString)
}

// RefreshToken fetches a valid token from keycloak using the refresh token.
func (c *Client) RefreshToken(realm string, refreshToken string) (*TokenInfo, error) {
	bodyString := fmt.Sprintf("refresh_token=%s&grant_type=refresh_token&client_id=admin-cli", refreshToken)
	return c.doTokenRequest(realm, bodyString)
}

// doTokenRequest makes a request for a token.
func (c *Client) doTokenRequest(realm string, body string) (*TokenInfo, error) {
	authPath := fmt.Sprintf("/auth/realms/%s/protocol/openid-connect/token", realm)
	path := c.apiURL.String() + authPath
	req, err := http.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}
	var tokenResponse *tokenJSON
	err = e3dbClients.MakeRawServiceCall(c.httpClient, req, &tokenResponse)
	if err != nil {
		return nil, err
	}
	tokenInfo := tokenResponse.toTokenInfo(time.Now().Add(time.Duration(-3)))
	return tokenInfo, nil
}

func setAuthorizationAndHostHeaders(req *http.Request, accessToken string) (*http.Request, error) {
	host, err := extractHostFromToken(accessToken)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("X-Forwarded-Proto", "https")
	// is this always the content type? fails with 415 if content type isn't specified
	req.Header.Add("Content-Type", "application/json")
	req.Host = host
	return req, nil
}
func setAuthorizationAndHostHeadersPlusSessionToken(req *http.Request, accessToken string, sessionToken string) (*http.Request, error) {
	host, err := extractHostFromToken(accessToken)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("X-Forwarded-Proto", "https")
	// This may need to be a Add
	req.Header.Set("X-Tozny-Session", sessionToken)
	req.Host = host
	return req, nil
}
func extractHostFromToken(token string) (string, error) {
	issuer, err := extractIssuerFromToken(token)
	if err != nil {
		return "", err
	}
	urlIssuer, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("Could not parse token issuer URL %+v with err: %+v", issuer, err)
	}

	return urlIssuer.Host, nil
}

func extractIssuerFromToken(token string) (string, error) {
	payload, _, err := jwt.Parse(token)
	if err != nil {
		return "", fmt.Errorf("Could not parse token %s with error: %+v", token, err)
	}
	var jot Token
	err = jwt.Unmarshal(payload, &jot)
	if err != nil {
		return "", fmt.Errorf("Could not unmarshal token with payload %+v with error: %+v", payload, err)
	}
	return jot.Issuer, nil
}

func (c *Client) post(accessToken string, data interface{}, url string) (string, error) {
	path := c.apiURL.String() + url
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(data)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", path, buf)
	if err != nil {
		return "", err
	}
	req, err = setAuthorizationAndHostHeaders(req, accessToken)
	if err != nil {
		return "", err
	}
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, nil)
	if err != nil {
		return "", e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	location := response.Header.Get("Location")
	return location, nil

}
func (c *Client) postJSONWithToznySessionToken(accessToken string, data interface{}, url string, sessionToken string) (string, error) {
	path := c.apiURL.String() + url
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(data)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", path, buf)
	if err != nil {
		return "", err
	}
	req, err = setAuthorizationAndHostHeadersPlusSessionToken(req, accessToken, sessionToken)
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, nil)
	if err != nil {
		return "", e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	location := response.Header.Get("Location")
	return location, nil

}
func (c *Client) postFormDataWithToznySessionToken(url, accessToken, sessionToken string, data url.Values, result interface{}) error {
	path := c.apiURL.String() + url
	req, err := http.NewRequest("POST", path, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req, err = setAuthorizationAndHostHeadersPlusSessionToken(req, accessToken, sessionToken)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, result)
	if err != nil {
		if response == nil {
			return err
		}
		return e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	return nil
}
func (c *Client) delete(accessToken string, data interface{}, url string) error {
	path := c.apiURL.String() + url
	req, err := http.NewRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	req, err = setAuthorizationAndHostHeaders(req, accessToken)
	if err != nil {
		return err
	}
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, nil)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	return nil

}
func (c *Client) get(accessToken string, data interface{}, url string) error {
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return err
	}
	req, err = setAuthorizationAndHostHeaders(req, accessToken)
	if err != nil {
		return err
	}
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, data)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	return nil

}
func (c *Client) put(accessToken string, data interface{}, url string) error {
	path := c.apiURL.String() + url
	buf := &bytes.Buffer{}
	err := json.NewEncoder(buf).Encode(data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", path, buf)
	if err != nil {
		return err
	}
	req, err = setAuthorizationAndHostHeaders(req, accessToken)
	if err != nil {
		return err
	}
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, nil)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, response.StatusCode)
	}
	return nil

}

// makeJSONCall sends a request, auto decoding the response to the result interface if sent.
func makeJSONCall(accessToken string, request *http.Request, result interface{}) error {
	client := &http.Client{}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return nil
	}

	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		requestURL := request.URL.String()
		return HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	return nil
}

// createVanillaRequest isolates duplicate code in creating http requests.
func createVanillaRequest(method string, path string, params interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	var request *http.Request
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return request, err
	}
	request, err = http.NewRequest(method, path, &buf)
	if err != nil {
		return request, HTTPError{
			HTTPStatus: 0,
			Message:    fmt.Sprintf("createVanillaRequest: error %s: creating request for %s %s %v", err, method, path, params),
		}
	}
	return request, nil
}

// makePlainTextCall sends a request, return the plain text response and error (if any).
func makePlainTextCall(accessToken string, request *http.Request) (string, error) {
	var body string
	client := &http.Client{}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Content-Type", "text/plain")

	response, err := client.Do(request)
	if err != nil {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return body, err
	}

	body = string(bodyBytes)
	return body, nil
}

// makePlainTextCall sends a request, return the plain text response and error (if any).
func makeNonAuthenticatedPlainTextCall(request *http.Request) (string, error) {
	var body string
	client := &http.Client{}

	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Content-Type", "text/plain")

	response, err := client.Do(request)
	if err != nil {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	defer response.Body.Close()
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		requestURL := request.URL.String()
		return body, HTTPError{
			HTTPStatus: response.StatusCode,
			Message:    fmt.Sprintf("%s: server http error %d", requestURL, response.StatusCode),
		}
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return body, err
	}

	body = string(bodyBytes)
	return body, nil
}

// CreateRealm creates the realm from its RealmRepresentation, returning error (if any).
func (c *Client) CreateRealm(accessToken string, realm RealmRepresentation) (string, error) {
	return c.post(accessToken, realm, realmRootPath)
}

// UpdateRealm update the top lovel information of the realm. Any user, role or client information
// from the realm representation will be ignored.
func (c *Client) UpdateRealm(accessToken string, realmName string, realm RealmRepresentation) error {
	return c.put(accessToken, realm, fmt.Sprintf("%s/%s", realmRootPath, realmName))
}

// DeleteRealm proxies the request for realm deletion, returning error (if any)
func (c *Client) DeleteRealm(accessToken string, realmName string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s", realmRootPath, realmName))
}

// GetRealm get the top level represention of the realm. Nested information like users are
// not included.
func (c *Client) GetRealm(accessToken string, realmName string) (RealmRepresentation, error) {
	var response = RealmRepresentation{}
	var err = c.get(accessToken, &response, fmt.Sprintf("%s/%s", realmRootPath, realmName))
	return response, err
}

// GetRealmRoles gets all roles for the realm
// GET /auth/admin/realms/demorealm/roles HTTP/1.1
// [{
//     "id": "f19e86ad-ddf2-4397-9a36-63bf02119fe8",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122"
// }, {
//     "id": "1776d0d5-5ed6-49fa-83fc-f589b9c43eed",
//     "name": "uma_authorization",
//     "description": "${role_uma_authorization}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122"
// }]
func (c *Client) GetRealmRoles(accessToken string, realmName string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, roleResourceName))
	return resp, err
}

// GetRealmRole gets a specific realm role’s representation
// GET /auth/admin/realms/demorealm/roles/Admin HTTP/1.1
// {
//     "id": "c4d3c739-ad50-421e-a9af-63b04ae4105d",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122",
//     "attributes": {}
// }
func (c *Client) GetRealmRoleByName(accessToken string, realmName string, roleName string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, roleResourceName, roleName))
	return resp, err
}

// GetRealmRole gets a specific realm role’s representation
// GET /auth/admin/realms/demorealm/roles-by-id/f19e86ad-ddf2-4397-9a36-63bf02119fe8
// {
//     "id": "f19e86ad-ddf2-4397-9a36-63bf02119fe8",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122",
//     "attributes": {}
// }
func (c *Client) GetRealmRoleByID(accessToken string, realmName string, roleId string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, roleByIDResourceName, roleId))
	return resp, err
}

// UpdateRealmRole updates a specific realm role’s representation
// PUT /auth/admin/realms/demorealm/roles-by-id/f19e86ad-ddf2-4397-9a36-63bf02119fe8
// {
//     "id": "f19e86ad-ddf2-4397-9a36-63bf02119fe8",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "b0b76f0e-3405-4d43-97da-4556d4cff122",
//     "attributes": {}
// }
func (c *Client) UpdateRealmRoleByID(accessToken string, realmName string, roleId string, role RoleRepresentation) error {
	return c.put(accessToken, role, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, roleByIDResourceName, roleId))
}

// CreateRealmRole creates a new role for the specified realm
// POST /auth/admin/realms/demorealm/roles HTTP/1.1
// {"name":"Admin Role","description":"Allow all."}
// 201
// Header: Location: http://localhost:8000/auth/admin/realms/demorealm/roles/Admin%sRole
func (c *Client) CreateRealmRole(accessToken string, realmName string, role RoleRepresentation) (string, error) {
	return c.post(accessToken, role, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, roleResourceName))
}

// DeleteRealmRole deletes the specified role from the specified realm
// DELETE /auth/admin/realms/demorealm/roles-by-id/c4d3c739-ad50-421e-a9af-63b04ae4105d HTTP/1.1
func (c *Client) DeleteRealmRole(accessToken string, realmName string, roleId string) error {
	var err = c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, roleByIDResourceName, roleId))
	return err
}

// GetGroupRealmRoleMappings get the realm level roles for the group or error (if any).
// > GET http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) GetGroupRealmRoleMappings(accessToken, realmName, groupId string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, realmResourceName))
	return resp, err
}

// AddGroupRealmRoleMappings adds realm role mapping(s) for the group, returning error (if any).
// > POST http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) AddGroupRealmRoleMappings(accessToken, realmName, groupId string, roleMappings []RoleRepresentation) error {
	_, err := c.post(accessToken, roleMappings, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, realmResourceName))
	return err
}

// RemoveGroupRealmRoleMappings removes realm role mapping(s) from the group
// > DELETE http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/realm
// ```json
// [
//   {
//     "id": "f815fc8a-5eb6-46c1-a454-5fbc8e1c6492",
//     "name": "offline_access",
//     "description": "${role_offline-access}",
//     "composite": false,
//     "clientRole": false,
//     "containerId": "4f0f8206-0ec4-4fd6-99eb-4e8c4b986c43"
//   }
// ]
// ```
func (c *Client) RemoveGroupRealmRoleMappings(accessToken, realmName, groupId string, roleMappings []RoleRepresentation) error {
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/groups/" + groupId + "/role-mappings/realm"
	request, err := createVanillaRequest("DELETE", path, roleMappings)
	if err != nil {
		return err
	}
	return makeJSONCall(accessToken, request, nil)
}

// GetUserDetails gets a detailed represention of the user with resolved groups and roles.
func (c *Client) GetUserDetails(accessToken string, realmName, username string) (UserDetailsRepresentation, error) {
	var resp = UserDetailsRepresentation{}
	encodedUsername := url.PathEscape(username)
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", userExtensionPath, realmName, adminResourceName, userResourceName, encodedUsername))
	return resp, err
}

// CreateGroup creates a new group for the realm
func (c *Client) CreateGroup(accessToken string, realmName string, group GroupRepresentation) (string, error) {
	return c.post(accessToken, group, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, groupResourceName))
}

// UpdateGroup updates an existing group for the realm
func (c *Client) UpdateGroup(accessToken string, realmName string, groupID string, group GroupRepresentation) error {
	return c.put(accessToken, group, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupID))
}

// DeleteGroup deletes a group from the realm
func (c *Client) DeleteGroup(accessToken string, realmName string, groupID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupID))
}

// GetGroups gets all groups for the realm
func (c *Client) GetGroups(accessToken string, realmName string) ([]GroupRepresentation, error) {
	var resp = []GroupRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, groupResourceName))
	return resp, err
}

// GetGroup gets a specific group’s representation
func (c *Client) GetGroup(accessToken string, realmName string, groupID string) (GroupRepresentation, error) {
	var resp = GroupRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupID))
	return resp, err
}

// GetDefaultGroups fetches the list of default groups for a realm
func (c *Client) GetDefaultGroups(accessToken string, realmName string) ([]GroupRepresentation, error) {
	resp := []GroupRepresentation{}
	err := c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, defaultGroupResourceName))
	return resp, err
}

// AddDefaultGroup places a new group for in the default realm groups by ID
func (c *Client) AddDefaultGroup(accessToken string, realmName string, groupID string) error {
	return c.put(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, defaultGroupResourceName, groupID))
}

// RemoveDefaultGroup deletes removes a group from the realm default groups list by ID
func (c *Client) RemoveDefaultGroup(accessToken string, realmName string, groupID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, defaultGroupResourceName, groupID))
}

// GetGroupsOfUser get the groups of the user.
func (c *Client) GetGroupsOfUser(accessToken string, realmName, userID string) ([]GroupRepresentation, error) {
	var resp = []GroupRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, groupResourceName))
	return resp, err
}

// GetUsers returns a list of users, filtered according to the query parameters.
// Parameters: email, first (paging offset, int), firstName, lastName, username,
// max (maximum result size, default = 100),
// search (string contained in username, firstname, lastname or email)
func (c *Client) GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (Users, error) {
	var err error
	var resp Users
	if len(paramKV)%2 != 0 {
		return nil, fmt.Errorf("the number of key/val parameters should be even")
	}
	url := fmt.Sprintf("%s/%s/%s", realmRootPath, targetRealmName, userResourceName)
	path := c.apiURL.String() + url

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return resp, err
	}
	if len(paramKV) > 0 {
		urlParams := req.URL.Query()
		// Sketchy
		for i := 0; i < len(paramKV); i += 2 {
			urlParams.Set(paramKV[i], paramKV[i+1])
		}
		req.URL.RawQuery = urlParams.Encode()
	}
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// CreateUser creates the user from its UserRepresentation. The username must be unique.
func (c *Client) CreateUser(accessToken string, reqRealmName, targetRealmName string, user UserRepresentation) (string, error) {
	return c.post(accessToken, user, fmt.Sprintf("%s/%s/%s", realmRootPath, targetRealmName, userResourceName))

}

// GetUser get the represention of the user.
func (c *Client) GetUser(accessToken string, realmName, userID string) (UserRepresentation, error) {
	var resp = UserRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID))
	return resp, err
}

// JoinGroup adds a user to a group by ID.
func (c *Client) JoinGroup(accessToken string, realmName, userID, groupID string) error {
	return c.put(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, groupResourceName, groupID))
}

// LeaveGroup removes a user from a group by ID.
func (c *Client) LeaveGroup(accessToken string, realmName, userID, groupID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, groupResourceName, groupID))
}

// DeleteUser deletes the user.
func (c *Client) DeleteUser(accessToken string, realmName, userID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID))
}

// GetSecret get the client secret. idClient is the id of client (not client-id).
func (c *Client) GetSecret(accessToken string, realmName, idClient string) (CredentialRepresentation, error) {
	var resp = CredentialRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, idClient, clientSecretResourceName))
	return resp, err
}

// CreateProtocolMapper creates a new protocol mapper for the client
func (c *Client) CreateProtocolMapper(accessToken string, realmName string, clientId string, protocolMapper ProtocolMapperRepresentation) (string, error) {
	return c.post(accessToken, protocolMapper, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientId, protocolMapperResourceName, modelsResourceName))
}

// DeleteProtocolMapper deletes a protocol mapper from the client
func (c *Client) DeleteProtocolMapper(accessToken string, realmName string, clientId string, protocolMapperID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientId, protocolMapperResourceName, modelsResourceName, protocolMapperID))
}

// GetProtocolMappers gets all mappers of a given protocol for the client
func (c *Client) GetProtocolMappers(accessToken string, realmName string, clientId string, protocol string) ([]ProtocolMapperRepresentation, error) {
	var resp = []ProtocolMapperRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientId, protocolMapperResourceName, protocolResourceName, protocol))
	return resp, err
}

// GetProtocolMapper gets a specific protocol mapper’s representation
func (c *Client) GetProtocolMapper(accessToken string, realmName string, clientId string, protocolmapperID string) (ProtocolMapperRepresentation, error) {
	var resp = ProtocolMapperRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientId, protocolMapperResourceName, modelsResourceName, protocolmapperID))
	return resp, err
}

// GetRealmDefaultClientScopes gets realm configuration for scopes which are added as client default scopes when a new client is created
// GET /auth/admin/realms/demorealm/default-default-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetRealmDefaultClientScopes(accessToken string, realmName string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s-%s", realmRootPath, realmName, defaultResourceName, defaultClientScopeResourceName))
	return resp, err
}

// RemoveRealmDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/default-default-client-scopes/2c683450-ae2d-48ef-ace3-bc9101b2c4d1 HTTP/1.1
// 204
func (c *Client) RemoveRealmDefaultClientScope(accessToken string, realmName, scope string) error {
	err := c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s-%s/%s", realmRootPath, realmName, defaultResourceName, defaultClientScopeResourceName, scope))
	return err
}

// GetDefaultClientScopes gets realm configuration for scopes which are added as client default scopes when a new client is created
// GET /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/default-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetDefaultClientScopes(accessToken string, realmName, client string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, client, defaultClientScopeResourceName))
	return resp, err
}

// RemoveDefaultClientScope changes the default client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/default-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) RemoveDefaultClientScope(accessToken string, realmName, client, scope string) error {
	err := c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, client, defaultClientScopeResourceName, scope))
	return err
}

// GetOptionalClientScopes gets realm configuration for scopes which are added as client optional scopes when a new client is created
// GET /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/optional-client-scopes HTTP/1.1
// [
//     {
//         "id":"3f4f9602-f843-48a6-9d24-0f9563eed5b0",
//         "name":"profile"
//     },
//     {
//         "id":"7efa02d9-0a1e-496d-abf7-d9edb80e47b3",
//         "name":"email"
//     },
//     {
//         "id":"2c683450-ae2d-48ef-ace3-bc9101b2c4d1",
//         "name":"web-origins"
//     }
// ]
func (c *Client) GetOptionalClientScopes(accessToken string, realmName, client string) ([]ClientScopeRepresentation, error) {
	var resp = []ClientScopeRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, client, optionalClientScopeResourceName))
	return resp, err
}

// RemoveOptionalClientScope changes the optional client scopes for a realm to add the scope represented by scopeId
// DELETE /auth/admin/realms/demorealm/clients/0d55d933-09f4-427d-a385-13f5ceb1656e/optional-client-scopes/7efa02d9-0a1e-496d-abf7-d9edb80e47b3 HTTP/1.1
// 204
func (c *Client) RemoveOptionalClientScope(accessToken string, realmName, client, scope string) error {
	err := c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, client, optionalClientScopeResourceName, scope))
	return err
}

// GetUserFederationProviderMapper returns the representation of the specified UserFederationProviderMapper or error (if any).
func (c *Client) GetUserFederationProviderMapper(accessToken string, realmName, userFederationProviderMapperID string) (UserFederationProviderMapperRepresentation, error) {
	resp := UserFederationProviderMapperRepresentation{}
	err := c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, componentsResourceName, userFederationProviderMapperID))
	return resp, err
}

// CreateUserFederationProviderMapper creates a user federation provider mapper for a realm for mapping attributes from
// synced users from an external source, returning the location of the created provider mapper or error (if any).
func (c *Client) CreateUserFederationProviderMapper(accessToken string, realmName string, userFederationProviderMapper UserFederationProviderMapperRepresentation) (string, error) {
	return c.post(accessToken, userFederationProviderMapper, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, componentsResourceName))
}

// GetUserFederationProviderMappers returns a list of UserFederationProviderMappers belonging to the realm
// or error (if any).
func (c *Client) GetUserFederationProviderMappers(accessToken string, realmName string, userFederationProviderID string, mapperType string) ([]UserFederationProviderMapperRepresentation, error) {
	resp := []UserFederationProviderMapperRepresentation{}

	url := fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, componentsResourceName)
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)

	urlParams := req.URL.Query()
	urlParams.Set("parent", userFederationProviderID)
	urlParams.Set("type", mapperType)
	req.URL.RawQuery = urlParams.Encode()

	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err

}

// DeleteUserFederationProviderMapper deletes the specified UserFederationProviderMapper from the realm.
func (c *Client) DeleteUserFederationProviderMapper(accessToken string, realmName, userFederationProviderMapperID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, componentsResourceName, userFederationProviderMapperID))
}

func (c *Client) GetRealmLevelRoleMappings(accessToken string, realmName, userID string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, realmResourceName))
	return resp, err
}

// AddRealmRolesToUserRoleMapping adds realm role mappings to a user, returning error (if any)
func (c *Client) AddRealmRolesToUserRoleMapping(accessToken string, realmName, userID string, roles []RoleRepresentation) error {
	_, err := c.post(accessToken, roles, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, realmResourceName))
	return err
}

// RemoveRealmRolesFromUserRoleMapping removes realm role mappings from a user, returning error (if any)
func (c *Client) RemoveRealmRolesFromUserRoleMapping(accessToken string, realmName, userID string, roles []RoleRepresentation) error {
	err := c.delete(accessToken, roles, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, realmResourceName))
	return err
}

// UpdateUser updates an Identity from a user representation, returning error (if any)
func (c *Client) UpdateUser(accessToken string, realmName string, userID string, userRepresenation UserRepresentation) error {
	err := c.put(accessToken, userRepresenation, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID))
	return err
}

// CreateUserFederationProvider creates a user federation provider for a realm for syncing users from an external source,
// returning the location of the created provider or error (if any).
func (c *Client) CreateUserFederationProvider(accessToken string, realmName string, userFederationProvider UserFederationProviderRepresentation) (string, error) {
	return c.post(accessToken, userFederationProvider, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, componentsResourceName))
}

// DeleteUserFederationProvider deletes the specified UserFederationProvider from the realm.
func (c *Client) DeleteUserFederationProvider(accessToken string, realmName, userFederationProviderID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, componentsResourceName, userFederationProviderID))
}

// GetUserFederationProvider returns the representation of the specified UserFederationProvider or error (if any).
func (c *Client) GetUserFederationProvider(accessToken string, realmName, userFederationProviderID string) (UserFederationProviderRepresentation, error) {
	resp := UserFederationProviderRepresentation{}
	err := c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, componentsResourceName, userFederationProviderID))
	return resp, err
}

// GetUserFederationProviders returns a list of UserFederationProviders belonging to the realm
// or error (if any).
func (c *Client) GetUserFederationProviders(accessToken string, realmName string, realmId string) ([]UserFederationProviderRepresentation, error) {
	resp := []UserFederationProviderRepresentation{}
	url := fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, componentsResourceName)
	path := c.apiURL.String() + url

	req, err := http.NewRequest("GET", path, nil)
	urlParams := req.URL.Query()
	urlParams.Set("parent", realmId)
	urlParams.Set("type", UserFederationProviderType)
	req.URL.RawQuery = urlParams.Encode()

	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// CreateAuthenticationExecutionForFlow add a new authentication execution to a flow.
// 'flowAlias' is the alias of the parent flow.
func (c *Client) CreateAuthenticationExecutionForFlow(accessToken string, realmName, flowAlias, provider string) (string, error) {
	var m = map[string]string{"provider": provider}
	return c.post(accessToken, m, fmt.Sprintf("%s/%s/%s/flows/%s/executions/execution", realmRootPath, realmName, authenticationResourceName, flowAlias))
}

// UpdateAuthenticationExecutionForFlow updates the authentication executions of a flow.
func (c *Client) UpdateAuthenticationExecutionForFlow(accessToken string, realmName, flowAlias string, authExecInfo AuthenticationExecutionInfoRepresentation) error {
	return c.put(accessToken, authExecInfo, fmt.Sprintf("%s/%s/%s/flows/%s/executions", realmRootPath, realmName, authenticationResourceName, flowAlias))
}

// CreateFlowWithExecutionForExistingFlow add a new flow with a new execution to an existing flow.
// 'flowAlias' is the alias of the parent authentication flow.
func (c *Client) CreateFlowWithExecutionForExistingFlow(accessToken string, realmName, flowAlias, alias, flowType, provider, description string) (string, error) {
	var m = map[string]string{"alias": alias, "type": flowType, "provider": provider, "description": description}
	return c.post(accessToken, m, fmt.Sprintf("%s/%s/%s/flows/%s/executions/flow", realmRootPath, realmName, authenticationResourceName, flowAlias))
}

// GetAuthenticationExecutionForFlow returns the authentication executions for a flow.
func (c *Client) GetAuthenticationExecutionForFlow(accessToken string, realmName, flowAlias string) ([]AuthenticationExecutionInfoRepresentation, error) {
	var resp = []AuthenticationExecutionInfoRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/flows/%s/executions", realmRootPath, realmName, authenticationResourceName, flowAlias))
	return resp, err
}

// CreateAuthenticationFlow creates a new authentication flow.
func (c *Client) CreateAuthenticationFlow(accessToken string, realmName string, authFlow AuthenticationFlowRepresentation) (string, error) {
	return c.post(accessToken, authFlow, fmt.Sprintf("%s/%s/%s/flows", realmRootPath, realmName, authenticationResourceName))
}

// GetSAMLDescriptor fetches the public XML IDP descriptor document for a realm
func (c *Client) GetSAMLDescriptor(realmName string) (string, error) {

	var description string
	path := c.apiURL.String() + "/auth/realms/" + realmName + "/protocol/saml/descriptor"
	request, err := createVanillaRequest("GET", path, nil)
	if err != nil {
		return description, err
	}
	description, err = makeNonAuthenticatedPlainTextCall(request)
	return description, err
}

// ExpireSession clears a session based on a valid session token
func (c *Client) ExpireSession(accessToken, realmName, sessionToken string) error {
	_, err := c.postJSONWithToznySessionToken(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", userExtensionPath, realmName, adminResourceName, logoutResourceName), sessionToken)
	return err
}

// InitiateLogin begins the login flow
func (c *Client) InitiateLogin(realmName string, loginURLEncoded InitiatePKCELogin) (*http.Response, error) {
	// Create Gentleman Client
	var gentlemanClient = gentleman.New()
	{
		gentlemanClient = gentlemanClient.URL(c.config.AddrAPI)
		gentlemanClient = gentlemanClient.Use(timeout.Request(c.config.Timeout))
	}
	// Create Request
	var req *gentleman.Request
	{
		var authPath = fmt.Sprintf(initiateLoginPath, realmName)
		req = gentlemanClient.Post()
		req = req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
		req = req.Path(authPath)
		req = req.Type("urlencoded")
		data := url.Values{}
		encoder.Encode(loginURLEncoded, data)
		req = req.BodyString(data.Encode())
	}
	// Send Request
	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return nil, fmt.Errorf("Could not Initiate Login: Error %+v", err)
		}
	}
	return resp.RawResponse, nil
}

// InitiateWebAuthnChallenge initiates the flow for registering a WebAuthn device
func (c *Client) InitiateWebAuthnChallenge(accessToken, sessionToken, realmDomain string) (InitiateWebAuthnChallengeResponse, error) {
	var result InitiateWebAuthnChallengeResponse
	path := fmt.Sprintf("/auth/realms/%s/%s/webauthn-challenge", realmDomain, mfaResourceName)
	err := c.postFormDataWithToznySessionToken(path, accessToken, sessionToken, url.Values{}, &result)
	return result, err
}

// RegisterWebAuthnDevice registers & persists the WebAuthn MFA device
func (c *Client) RegisterWebAuthnDevice(accessToken, sessionToken, realmDomain string, data RegisterWebAuthnDeviceRequest) error {
	query := url.Values{}
	query.Add("tab_id", data.TabID) // post requires tab id in the query to map to previous session
	path := fmt.Sprintf("/auth/realms/%s/%s/webauthn-register?%s", realmDomain, mfaResourceName, query.Encode())
	formData := url.Values{
		"clientDataJSON":        {data.ClientDataJSON},
		"attestationObject":     {data.AttestationObject},
		"publicKeyCredentialId": {data.PublicKeyCredentialID},
		"authenticatorLabel":    {data.AuthenticatorLabel},
	}
	err := c.postFormDataWithToznySessionToken(path, accessToken, sessionToken, formData, nil)
	return err
}

func (c *Client) GetUserCredentials(accessToken string, realmName, userID string) ([]CredentialRepresentation, error) {
	var resp = []CredentialRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/credentials", realmRootPath, realmName, userResourceName, userID))
	return resp, err
}

// requestWithQueryParams creates a request with query params
func (c *Client) requestWithQueryParams(accessToken string, req *http.Request, data interface{}) error {
	req, err := setAuthorizationAndHostHeaders(req, accessToken)
	if err != nil {
		return err
	}
	response, err := e3dbClients.ReturnRawServiceCall(c.httpClient, req, data)
	if err != nil {
		return e3dbClients.NewError(err.Error(), req.URL.Path, response.StatusCode)
	}
	return nil
}
