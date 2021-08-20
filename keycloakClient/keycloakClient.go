package keycloakClient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/gbrlsnchs/jwt/v2"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

const (
	realmRootPath            = "/auth/admin/realms"
	userExtensionPath        = "/auth/realms"
	clientResourceName       = "clients"
	roleResourceName         = "roles"
	roleByIDResourceName     = "roles-by-id"
	groupResourceName        = "groups"
	roleMappingResourceName  = "role-mappings"
	realmResourceName        = "realm"
	adminResourceName        = "admin"
	userResourceName         = "users"
	defaultGroupResourceName = "default-groups"
)

var (
	RefreshExhaustedError = errors.New("refresh token exhausted")
	SessionExpiredError   = errors.New("auth session expired")
	// KeycloakTokenInfoLock allows for access control so only one routine is able to access the Keycloak Token Info
	KeycloakTokenInfoLock = &sync.Mutex{}
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
	return &Client{
		tokenProviderURL: urlToken,
		apiURL:           urlApi,
		httpClient:       &httpClient,
		tokens:           map[string]*TokenInfo{},
	}, nil
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
	key := realm + username
	KeycloakTokenInfoLock.Lock()
	// Get exclusive access to the token
	tokenInfo, exists := c.tokens[key]
	KeycloakTokenInfoLock.Unlock()
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

// GetClient get the representation of the client. idClient is the id of client (not client-id).
func (c *Client) GetClient(accessToken string, realmName string, idClient string) (ClientRepresentation, error) {
	var response = ClientRepresentation{}
	var err = c.get(accessToken, &response, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, idClient))
	return response, err
}

// UpdateClient updates the client.
func (c *Client) UpdateClient(accessToken string, realmName string, clientID string, client ClientRepresentation) error {
	return c.put(accessToken, client, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID))
}

// DeleteClient deletes specified client from the realm. id is the id of client (not client-id).
func (c *Client) DeleteClient(accessToken string, realmName string, clientID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID))
}

// CreateClient creates a client
func (c *Client) CreateClient(accessToken string, realmName string, client ClientCreateRequest) (string, error) {
	return c.post(accessToken, client, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, clientResourceName))
}

// GetClients returns a list of clients belonging to the realm.
// Parameters: clientId (filter by clientId),
// viewableOnly (filter clients that cannot be viewed in full by admin, default="false")
func (c *Client) GetClients(accessToken string, realmName string, paramKV ...string) ([]ClientRepresentation, error) {
	var err error
	var resp = []ClientRepresentation{}
	if len(paramKV)%2 != 0 {
		return nil, fmt.Errorf("the number of key/val parameters should be even")
	}
	url := fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, clientResourceName)
	path := c.apiURL.String() + url

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return resp, err
	}
	if len(paramKV) > 0 {
		urlParams := req.URL.Query()
		// Sketchy
		for i := 0; i < len(paramKV)%2; i += 2 {
			urlParams.Set(paramKV[i], paramKV[i+1])
		}
		req.URL.RawQuery = urlParams.Encode()
	}
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}
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

// GetClientRoles gets all roles for the realm or client
func (c *Client) GetClientRoles(accessToken string, realmName string, clientID string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName))
	return resp, err
}

// CreateClientRole creates a new role for the realm or client
func (c *Client) CreateClientRole(accessToken string, realmName string, clientID string, role RoleRepresentation) (string, error) {
	return c.post(accessToken, role, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName))
}

// DeleteRole deletes a role
func (c *Client) DeleteRole(accessToken string, realmName string, clientID string, roleID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName, roleID))
}

// GetClientRole gets a specific client role’s representation
func (c *Client) GetClientRole(accessToken string, realmName string, clientID string, roleID string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName, roleID))
	return resp, err
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

// GetGroupClientRoleMappings returns the assigned client roles for a group and error (if any).
// >	GET http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) GetGroupClientRoleMappings(accessToken, realmName, groupId, clientId string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, clientResourceName, clientId))
	return resp, err
}

// AddGroupClientRoleMappings adds client role mappings for a group, returning error (if any)
// >	POST http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) AddGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	_, err := c.post(accessToken, roleMappings, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, clientResourceName, clientId))
	return err
}

// RemoveGroupClientRoleMappings removes client role mapping(s) from a group, returning error (if any)
// >	DELETE http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) RemoveGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/groups/" + groupId + "/role-mappings/clients/" + clientId
	request, err := createVanillaRequest("DELETE", path, roleMappings)
	if err != nil {
		return err
	}
	return makeJSONCall(accessToken, request, nil)
}

// GetUserDetails gets a detailed represention of the user with resolved groups and roles.
func (c *Client) GetUserDetails(accessToken string, realmName, username string) (UserDetailsRepresentation, error) {
	var resp = UserDetailsRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", userExtensionPath, realmName, adminResourceName, userResourceName, username))
	return resp, err
}

// CreateGroup creates a new group for the realm
func (c *Client) CreateGroup(accessToken string, realmName string, group GroupRepresentation) (string, error) {
	return c.post(accessToken, group, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, groupResourceName))
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
