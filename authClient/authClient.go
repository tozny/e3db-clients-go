// Package authClient implements an HTTP client for communications
// with an e3db Auth service.
package authClient

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "github.com/tozny/e3db-clients-go"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"
    "net/http"
)

const (
    AuthServiceBasePath = "v1/auth" //HTTP PATH prefix for calls to the auth service.
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
    request, err := http.NewRequest("POST", c.Host+"/"+AuthServiceBasePath+"/validate", &buf)
    if err != nil {
        return result, err
    }
    err = e3dbClients.MakeE3DBServiceCall(c, ctx, request, &result)
    return result, err
}

// AuthHTTPClient returns an http client that can be used for
// making authenticated requests to an e3db endpoint using the provided context.
func (c *E3dbAuthClient) AuthHTTPClient(ctx context.Context) *http.Client {
    if c.httpClient == nil {
        c.httpClient = c.oauth2Helper.Client(ctx)
    }
    return c.httpClient
}

// New returns a new E3dbAuthClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbAuthClient {
    return E3dbAuthClient{
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
