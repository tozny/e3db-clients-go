// Package authClient implements an HTTP client for communications
// with an e3db Auth service.
package authClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/utils-go/server"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	AuthServiceBasePath = "/v1/auth" //HTTP PATH prefix for calls to the auth service.
)

//E3dbAuthClient implements an http client for communication with an e3db auth service.
type E3dbAuthClient struct {
	APIKey       string
	APISecret    string
	Host         string
	oauth2Helper clientcredentials.Config
	httpClient   *http.Client
}

// GetToken attempts to retrieve and return a valid oauth2 token based on the clients
// credentials, returning token and error(if any).
func (c *E3dbAuthClient) GetToken(ctx context.Context) (*oauth2.Token, error) {
	return c.oauth2Helper.Token(ctx)
}

func (c *E3dbAuthClient) ValidateToken(ctx context.Context, params ValidateTokenRequest) (*ValidateTokenResponse, error) {
	var result *ValidateTokenResponse
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return result, err
	}
	request, err := http.NewRequest("POST", c.Host+AuthServiceBasePath+"/validate", &buf)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c, ctx, request, &result)
	return result, internalError
}

// AuthenticateE3DBClient validates the provided token belongs to
// an internal OR external e3db client,
// returning the clientID and validity of the provided token, and error (if any).
// This method is a wrapper over #ValidateToken for the express purpose
// of allowing utils-go to support AuthN without taking
// a direct and cyclical dependency on this package
func (c *E3dbAuthClient) AuthenticateE3DBClient(ctx context.Context, token string, internal bool) (clientID string, valid bool, err error) {
	params := ValidateTokenRequest{
		Token:    token,
		Internal: internal,
	}
	validateTokenResponse, err := c.ValidateToken(ctx, params)
	if err != nil {
		return "", false, err
	}
	return validateTokenResponse.ClientId, validateTokenResponse.Valid, err
}

// AuthHTTPClient returns an http client that can be used for
// making requests to Tozny services that require bearer auth,
// automatically fetching and refreshing the token as needed
func (c *E3dbAuthClient) AuthHTTPClient() *http.Client {
	if c.httpClient == nil {
		// Use a background context as while token refreshing is driven by client actions
		// it is state maintained server side
		c.httpClient = c.oauth2Helper.Client(context.Background())
	}
	return c.httpClient
}

// HealthCheck checks whether the auth service is up,
// returning error if unable to connect to the service.
func (c *E3dbAuthClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequest(http.MethodGet, c.Host+AuthServiceBasePath+server.HealthCheckPathSuffix, nil)
	if err != nil {
		return err
	}
	if err := e3dbClients.MakePublicCall(ctx, req, nil); err != nil { // run request to auth healthcheck
		return err
	}
	return nil
}

// New returns a new E3dbAuthClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbAuthClient {
	return E3dbAuthClient{
		APIKey:    config.APIKey,
		APISecret: config.APISecret,
		Host:      config.AuthNHost,
		oauth2Helper: clientcredentials.Config{
			ClientID:     config.APIKey,
			ClientSecret: config.APISecret,
			TokenURL:     fmt.Sprintf("%s%s/token", config.AuthNHost, AuthServiceBasePath),
		},
	}
}
