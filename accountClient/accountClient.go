package accountClient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
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

// CreateAccount attempts to create an e3db account using the provided params, returning created account and error (if any).
func (c *E3dbAccountClient) CreateAccount(ctx context.Context, params CreateAccountRequest) (*CreateAccountResponse, error) {
	var result *CreateAccountResponse
	path := c.Host + "/" + AccountServiceBasePath + "/profile"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	internalErr := e3dbClients.MakeRawServiceCall(&http.Client{}, request, &result)
	return result, internalErr
}

// InternalGetClientAccount attempts to get the account id and other account information for the specified client id
func (c *E3dbAccountClient) InternalGetClientAccount(ctx context.Context, clientID string) (*InternalGetClientAccountResponse, error) {
	var result *InternalGetClientAccountResponse
	path := c.Host + "/internal/" + AccountServiceBasePath + "/clients/" + clientID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// RegistrationToken validates a registration token with the account service and fetches its permissions
func (c *E3dbAccountClient) RegistrationToken(ctx context.Context, token string) (*RegTokenInfo, error) {
	result := RegTokenInfo{
		Permissions: RegTokenPermissions{
			Enabled:      true,
			AllowedTypes: []string{"general"},
		},
	}
	path := c.Host + "/internal/" + AccountServiceBasePath + "/token"
	request, err := e3dbClients.CreateRequest("POST", path, map[string]string{"token": token})
	if err != nil {
		return &result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return &result, err
}

// ValidateAuthToken validates a bearer token issued by the account service
func (c *E3dbAccountClient) ValidateAuthToken(ctx context.Context, params ValidateTokenRequest) (*ValidateTokenResponse, error) {
	var result *ValidateTokenResponse
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return result, err
	}
	request, err := http.NewRequest("POST", c.Host+"/"+AccountServiceBasePath+"/auth/validate", &buf)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// InternalGetStripeID attempts to get account information for the specified account ID. Currently the only account information that is returned is the stripeID
func (c *E3dbAccountClient) InternalGetAccountInfo(ctx context.Context, accountID string) (*InternalGetAccountInfoResponse, error) {
	var result *InternalGetAccountInfoResponse
	path := c.Host + "/internal/" + AccountServiceBasePath + "/account-info/" + accountID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// ServiceCheck checks whether the account service is up and working.
func (c *E3dbAccountClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + "/" + AccountServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
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
