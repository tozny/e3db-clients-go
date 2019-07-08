package identityClient

import (
	"context"
	"net/http"

	"github.com/tozny/e3db-clients-go"
)

const (
	identityServiceBasePath = "/v1/identity" // HTTP PATH prefix for calls to the Identity service
	realmResourceName       = "realm"
)

// E3dbIdentityClient implements an http client for communication with an e3db Identity service.
type E3dbIdentityClient struct {
	Host       string
	authClient *http.Client
}

// CreateRealm creates a realm using the specified parameters,
// returning the created realm (including it's associated sovereign) and error (if any).
func (c *E3dbIdentityClient) CreateRealm(ctx context.Context, params CreateRealmRequest) (*CreateRealmResponse, error) {
	var createRealmResponse *CreateRealmResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return createRealmResponse, err
	}
	// TODO: signature based request
	err = e3dbClients.MakeRawServiceCall(c.authClient, request, &createRealmResponse)
	return createRealmResponse, err
}

// ServiceCheck checks whether the identity service is up and working.
// returning error if unable to connect service
func (c *E3dbIdentityClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.authClient, request, nil)
	return err
}

// HealthCheck checks whether the identity service is up,
// returning error if unable to connect to the service.
func (c *E3dbIdentityClient) HealthCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/healthcheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.authClient, request, nil)
	return err
}

// New returns a new E3dbHookClient configured with the provided values
func New(config e3dbClients.ClientConfig) E3dbIdentityClient {
	return E3dbIdentityClient{
		Host: config.Host,
		// In the future this client will make authenticated calls using signature based auth
		authClient: &http.Client{},
	}
}
