package accountClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"net/http"
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

// CreateAccount attempts to create an e3db account using the provided params, returning created account and error (if any).
func (c *E3dbAccountClient) CreateAccount(ctx context.Context, params CreateAccountRequest) (*CreateAccountResponse, error) {
	var result *CreateAccountResponse
	path := c.Host + "/" + AccountServiceBasePath + "/profile"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeRawServiceCall(&http.Client{}, request, &result)
	return result, err
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

// ServiceCall will make a call to a path based on the service root, using the method and params sent.
func (c *E3dbAccountClient) ServiceCall(ctx context.Context, path, method string, params interface{}, result interface{}) error {
	internalPath := c.Host + "/" + AccountServiceBasePath + path
	request, err := e3dbClients.CreateRequest(method, internalPath, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return err
}

// InternalServiceCall will make a call to a path based on the internal service root, using the method and params sent.
func (c *E3dbAccountClient) InternalServiceCall(ctx context.Context, path, method string, params interface{}, result interface{}) error {
	internalPath := c.Host + "/internal/" + AccountServiceBasePath + path
	request, err := e3dbClients.CreateRequest(method, internalPath, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return err
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
