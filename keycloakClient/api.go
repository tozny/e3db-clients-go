package keycloakClient

import (
	"net/http"
	"net/url"
	"time"
)

// TokenInfo represents a full oAuth2 JWT token response with expiration and refresh.
type TokenInfo struct {
	TokenType      string
	AccessToken    string
	Expires        time.Time
	RefreshToken   string
	RefreshExpires time.Time
	refresher      *time.Timer
}

// Client is the keycloak client which contains a map of current tokens.
type Client struct {
	tokenProviderURL *url.URL
	apiURL           *url.URL
	httpClient       *http.Client
	tokens           map[string]*TokenInfo
}

// Config is the http config used to create a client.
type Config struct {
	AddrTokenProvider string
	AddrAPI           string
	Timeout           time.Duration
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token in JSON form.
type tokenJSON struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int32  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int32  `json:"refresh_expires_in"`
}
