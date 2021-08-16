package keycloakClient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

const ()

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
