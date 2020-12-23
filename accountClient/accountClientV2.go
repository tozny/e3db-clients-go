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
	APIKey    string
	APISecret string
	Host      string
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
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
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
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InitEmailUpdate attempts to start the email update process
func (c *E3dbAccountClientV2) InitiateEmailUpdate(ctx context.Context, params InitiateUpdateEmailRequest) (*InitiateUpdateEmailResponse, error) {
	var result *InitiateUpdateEmailResponse
	path := c.Host + "/" + AccountServiceV2BasePath + "/profile/email"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), request, &result)
	return result, err
}

// NewV2 returns a new E3dbAccountClient configured with the specified apiKey and apiSecret values.
func NewV2(config e3dbClients.ClientConfig) E3dbAccountClientV2 {
	authService := authClient.New(config)
	return E3dbAccountClientV2{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
