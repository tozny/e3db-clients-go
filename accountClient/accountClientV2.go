package accountClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

// HTTP PATH prefix for calls to the e3db Account service for v2
const (
	AccountServiceV2BasePath = "v2/account"
)

// E3dbAccountClient implements an http client for communication with an e3db Account service.
type E3dbAccountClientV2 struct {
	APIKey         string
	APISecret      string
	Host           string
	ClientID       string
	httpClient     *http.Client
	EncryptionKeys e3dbClients.EncryptionKeys
	SigningKeys    e3dbClients.SigningKeys
	*authClient.E3dbAuthClient
	requester request.Requester
}

// ServiceCheck checks whether the account service V2 is up and working.
// returning error if unable to connect service
func (c *E3dbAccountClientV2) ServiceCheck(ctx context.Context) error {
	path := c.Host + "/" + AccountServiceV2BasePath + "/servicecheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakePublicCall(ctx, c.requester, req, nil)
	return err
}

// HealthCheck checks whether the account service V2 is up,
// returning error if unable to connect to the service.
func (c *E3dbAccountClientV2) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + AccountServiceV2BasePath + "/healthcheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakePublicCall(ctx, c.requester, req, nil)
	return err
}

// DeleteAccount deletes all the resources for an account, this endpoint has queen authentication and can be disabled
func (c *E3dbAccountClientV2) DeleteAccount(ctx context.Context, params DeleteAccountRequestData) error {
	path := c.Host + "/" + AccountServiceV2BasePath + "/" + params.AccountID.String()
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, c.requester, request, c.SigningKeys, c.ClientID, nil)
}

// NewV2 returns a new E3dbAccountClient configured with the specified apiKey and apiSecret values.
func NewV2(config e3dbClients.ClientConfig) E3dbAccountClientV2 {
	authService := authClient.New(config)
	return E3dbAccountClientV2{
		Host:           config.Host,
		SigningKeys:    config.SigningKeys,
		EncryptionKeys: config.EncryptionKeys,
		ClientID:       config.ClientID,
		httpClient:     &http.Client{},
		E3dbAuthClient: &authService,
		requester:      request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
