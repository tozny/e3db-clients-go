package activityClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	ActivityServiceBasePath = "/v1/activity-service"
)

// E3dbActivityClient implements an http client for communication with an e3db activity service.
type E3dbActivityClient struct {
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

// New returns a new E3dbActivityClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbActivityClient {
	authService := authClient.New(config)
	return E3dbActivityClient{
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
func (c *E3dbActivityClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + ActivityServiceBasePath + "/servicecheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.requester, req, nil)
	return err
}

// HealthCheck checks whether the service is up,
// returning error if unable to connect to the service.
func (c *E3dbActivityClient) HealthCheck(ctx context.Context) error {
	path := c.Host + ActivityServiceBasePath + "/healthcheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.requester, req, nil)
	return err
}
