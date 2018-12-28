// Package authClient implements an HTTP client for communications
// with an e3db Auth service.
package authClient

import (
    "context"
    "fmt"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
    "os"
)

const (
    AuthServiceBasePath = "v1/auth" //HTTP PATH prefix for calls to the auth service.
)

var (
    e3dbBaseURL = os.Getenv("E3DB_API_URL") //HTTP host value for calls to the e3db API.
)

//E3DBAuthClient implements an http client for communication with an e3db auth service.
type E3DBAuthClient struct {
    APIKey       string
    APISecret    string
    oauth2Helper clientcredentials.Config
}

// GetToken attempts to retrieve and return a valid oauth2 token based on the clients
// credentials, returning token and error(if any).
func (c *E3DBAuthClient) GetToken(ctx context.Context) (*oauth2.Token, error) {
    return c.oauth2Helper.Token(ctx)
}

// New returns a new E3DBAuthClient configured with the specified apiKey and apiSecret values.
func New(apiKey string, apiSecret string) E3DBAuthClient {
    return E3DBAuthClient{
        APIKey:    apiKey,
        APISecret: apiSecret,
        oauth2Helper: clientcredentials.Config{
            ClientID:     apiKey,
            ClientSecret: apiSecret,
            TokenURL:     fmt.Sprintf("%s/%s/token", e3dbBaseURL, AuthServiceBasePath),
        },
    }
}
