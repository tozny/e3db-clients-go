package secureComputeClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	secureComputeServiceBasePath = "/v1/secure-compute" // HTTP PATH prefix for calls to the Secure Compute Service
)

// E3dbSecureComputeClient implements an http client for communication with an e3db secure compute service.
type E3dbSecureComputeClient struct {
	Host           string
	ClientID       string
	APIKey         string
	APISecret      string
	httpClient     *http.Client
	EncryptionKeys e3dbClients.EncryptionKeys
	SigningKeys    e3dbClients.SigningKeys
	*authClient.E3dbAuthClient
	requester request.Requester
}

// New returns a new E3dbSecureComputeClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbSecureComputeClient {
	authService := authClient.New(config)
	return E3dbSecureComputeClient{
		Host:           config.Host,
		SigningKeys:    config.SigningKeys,
		EncryptionKeys: config.EncryptionKeys,
		ClientID:       config.ClientID,
		httpClient:     &http.Client{},
		E3dbAuthClient: &authService,
		requester:      request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}

// ServiceCheck checks whether the service is up and working.
// returning error if unable to connect service
func (c *E3dbSecureComputeClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + secureComputeServiceBasePath + "/servicecheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.requester, req, nil)
	return err
}

// HealthCheck checks whether the service is up,
// returning error if unable to connect to the service.
func (c *E3dbSecureComputeClient) HealthCheck(ctx context.Context) error {
	path := c.Host + secureComputeServiceBasePath + "/healthcheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.requester, req, nil)
	return err
}
