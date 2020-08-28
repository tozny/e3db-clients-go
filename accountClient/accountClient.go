package accountClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

const (
	AccountServiceBasePath = "v1/account" //HTTP PATH prefix for calls to the e3db Account service
)

//E3dbAccountClient implements an http client for communication with an e3db Account service.
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

// InternalAccountInfo attempts to get the account info for an accountID,
// requires the bootstrap client.
func (c *E3dbAccountClient) InternalAccountInfo(ctx context.Context, accountID string) (*InternalAccountInfoResponse, error) {
	var result *InternalAccountInfoResponse

	path := c.Host + "/internal/" + AccountServiceBasePath + "/info/" + accountID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
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

// RegisterClient registers a client with using the account service which proxies to the client service,
// this method is intended for TESTING the functionality of the integrated client service. Not intended for future use.
func (c *E3dbAccountClient) RegisterClient(ctx context.Context, params ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	var result *ClientRegistrationResponse
	path := c.Host + "/" + AccountServiceBasePath + "/e3db/clients/register"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	resp, err := e3dbClients.ReturnE3dbServiceCall(c.E3dbAuthClient, ctx, request, &result)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	// TODO: add this response as a field in account service so we don't have to parse it from the header here.
	backupClient := resp.Header.Get("X-Backup-Client")
	result.RootClientID = backupClient
	return result, err
}

// RegisterClient registers a client via a proxied call to client service by the account service.
// This method is intended for TESTING the functionality of the integrated client service. Not intended for future use.
func (c *E3dbAccountClient) ProxyiedRegisterClient(ctx context.Context, params ProxiedClientRegistrationRequest) (*ProxiedClientRegisterationResponse, error) {
	var result *ProxiedClientRegisterationResponse
	path := c.Host + "/" + AccountServiceBasePath + "/e3db/clients/register"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	resp, err := e3dbClients.ReturnRawServiceCall(&http.Client{}, request, &result)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	// TODO: add this response as a field in account service so we don't have to parse it from the header here.
	backupClient := resp.Header.Get("X-Backup-Client")
	result.RootClientID = backupClient
	return result, err
}

// CreateRegistrationToken makes a call to account service to create a registration token
func (c *E3dbAccountClient) CreateRegistrationToken(ctx context.Context, params CreateRegistrationTokenRequest) (*CreateRegTokenResponse, error) {
	var result *CreateRegTokenResponse
	path := c.Host + "/" + AccountServiceBasePath + "/tokens"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	// TODO: Not actually a `proxied user call` but account service serves it's own auth...
	// Consider a renaming of MakeProxiedUserCall
	err = e3dbClients.MakeProxiedUserCall(ctx, params.AccountServiceToken, request, &result)
	return result, err
}

// DeleteRegistrationToken attempts to delete the specified registration token, returning error (if any).
func (c *E3dbAccountClient) DeleteRegistrationToken(ctx context.Context, params DeleteRegistrationTokenRequest) error {
	path := c.Host + "/" + AccountServiceBasePath + fmt.Sprintf("/tokens/%s", params.Token)
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return e3dbClients.NewError(err.Error(), path, 0)
	}
	return e3dbClients.MakeProxiedUserCall(ctx, params.AccountServiceToken, request, nil)
}

// RegistrationToken validates a registration token with the account service and fetches its permissions
func (c *E3dbAccountClient) RegistrationToken(ctx context.Context, token string) (*RegTokenInfo, error) {
	var result RegTokenInfo
	path := c.Host + "/internal/" + AccountServiceBasePath + "/token"
	request, err := e3dbClients.CreateRequest("POST", path, map[string]string{"token": token})
	if err != nil {
		return &result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return &result, err
}

// IncrementTokenUse increases the number of uses on a registration token. It does not disable tokens
func (c *E3dbAccountClient) IncrementTokenUse(ctx context.Context, token string) (*RegTokenInfo, error) {
	path := c.Host + "/internal/" + AccountServiceBasePath + "/token/" + token + "/increment"
	result := RegTokenInfo{}
	request, err := e3dbClients.CreateRequest("PUT", path, nil)
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

// ServiceCheck checks whether the account service is up and working.
// returning error if unable to connect service
func (c *E3dbAccountClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + "/" + AccountServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

// HealthCheck checks whether the account service is up,
// returning error if unable to connect to the service.
func (c *E3dbAccountClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + AccountServiceBasePath + "/healthcheck"
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
