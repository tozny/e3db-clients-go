package accountClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

const (
	AccountServiceBasePath = "v1/account" //HTTP PATH prefix for calls to the e3db Account service
)

//E3dbAccountClient implements an http client for communication with an e3db PDS service.
type E3dbAccountClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

// InternalGetClientAccount attempts to get the account id and other account information for the specified client id
func (c *E3dbAccountClient) InternalGetClientAccount(ctx context.Context, clientID string) (*InternalGetClientAccountResponse, error) {
	var result *InternalGetClientAccountResponse
	path := c.Host + "/internal/" + AccountServiceBasePath + "/clients/" + clientID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// New returns a new E3dbAccountClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbAccountClient {
	authService := authClient.New(config)
	return E3dbAccountClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
	}
}
