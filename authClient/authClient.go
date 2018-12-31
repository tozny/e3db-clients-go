// Package authClient implements an HTTP client for communications
// with an e3db Auth service.
package authClient

import (
    "context"
    "fmt"
    "github.com/tozny/e3db-clients-go"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
    "net/http"
)

const (
    AuthServiceBasePath = "v1/auth" //HTTP PATH prefix for calls to the auth service.
)

//E3DBAuthClient implements an http client for communication with an e3db auth service.
type E3DBAuthClient struct {
    APIKey       string
    APISecret    string
    Host         string
    oauth2Helper clientcredentials.Config
}

// GetToken attempts to retrieve and return a valid oauth2 token based on the clients
// credentials, returning token and error(if any).
func (c *E3DBAuthClient) GetToken(ctx context.Context) (*oauth2.Token, error) {
    return c.oauth2Helper.Token(ctx)
}

// AuthHTTPClient returns an http client that can be used for
// making authenticated requests to an e3db endpoint using the provided context.
func (c *E3DBAuthClient) AuthHTTPClient(ctx context.Context) *http.Client {
    return c.oauth2Helper.Client(ctx)
}

// New returns a new E3DBAuthClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3DBAuthClient {
    return E3DBAuthClient{
        APIKey:    config.APIKey,
        APISecret: config.APISecret,
        Host:      config.Host,
        oauth2Helper: clientcredentials.Config{
            ClientID:     config.APIKey,
            ClientSecret: config.APISecret,
            TokenURL:     fmt.Sprintf("%s/%s/token", config.Host, AuthServiceBasePath),
        },
    }
}
