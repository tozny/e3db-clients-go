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

// Subscribe allows a TozStore Client to subscribe for an available computation for their data
func (c *E3dbSecureComputeClient) Subscribe(ctx context.Context, params SubscriptionRequest) (*SubscriptionResponse, error) {
	var result *SubscriptionResponse
	path := c.Host + secureComputeServiceBasePath + "/subscription"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// UpdateSubscription Updates information on subscribed computation
func (c *E3dbSecureComputeClient) UpdateSubscription(ctx context.Context, params UpdateSubscriptionRequest) error {
	path := c.Host + secureComputeServiceBasePath + "/subscription"
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
}

// FetchSubsciption Fetches all Computations the TozStore Client is registered for
func (c *E3dbSecureComputeClient) FetchSubsciptions(ctx context.Context, params FetchSubscriptionsRequest) (*ComputationResponse, error) {
	var result *ComputationResponse
	path := c.Host + secureComputeServiceBasePath + "/subscription"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("client_id", params.ToznyClientID.String())
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// Unsubscribe ends the subscription for a TozStore Client from a computation
func (c *E3dbSecureComputeClient) Unsubscribe(ctx context.Context, params UnsubscribeRequest) error {
	path := c.Host + secureComputeServiceBasePath + "/subscription"
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	urlParams := req.URL.Query()
	urlParams.Set("client_id", params.ToznyClientID.String())
	urlParams.Set("computation_id", params.ComputationID.String())
	req.URL.RawQuery = urlParams.Encode()
	return e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
}

// ComputeAnalysis runs a computation for a subscribed Tozstore Client
func (c *E3dbSecureComputeClient) ComputeAnalysis(ctx context.Context, params ComputationRequest) (*ComputationResponse, error) {
	var result *ComputationResponse
	path := c.Host + secureComputeServiceBasePath + "/compute/" + params.ComputationID.String()
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// FetchAvailableComputations fetches all available computations to the TozStore Client
func (c *E3dbSecureComputeClient) FetchAvailableComputations(ctx context.Context) (*ComputationResponse, error) {
	var result *ComputationResponse
	path := c.Host + secureComputeServiceBasePath + "/compute"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}
