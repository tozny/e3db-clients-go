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
	realmRootPath      = "/auth/admin/realms"
	clientResourceName = "clients"
)

var (
	RefreshExhaustedError = errors.New("refresh token exhausted")
	SessionExpiredError   = errors.New("auth session expired")
	// KeycloakTokenInfoLock allows for access control so only one routine is able to access the Keycloak Token Info
	KeycloakTokenInfoLock = &sync.Mutex{}
)

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

type Token struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
	Username       string `json:"preferred_username,omitempty"`
}

type header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}
