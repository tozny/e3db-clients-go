package clientServiceClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

var (
	ClientServiceBasePath = "v1/client/"
)

//ClientServiceClient implements an http client for communication with the client service.
type ClientServiceClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

// AdminList makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminList(ctx context.Context, params AdminListRequest) (*AdminListResponse, error) {
	var result *AdminListResponse
	path := c.Host + "/" + ClientServiceBasePath + "admin"
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// AdminGet makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminGet(ctx context.Context, clientID string) (*AdminGetResponse, error) {
	var result *AdminGetResponse
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + clientID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// Register registers a client.
func (c *ClientServiceClient) Register(ctx context.Context, params ClientRegisterRequest) (*ClientRegisterResponse, error) {
	var result *ClientRegisterResponse
	path := c.Host + "/" + ClientServiceBasePath
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakePublicCall(ctx, request, &result)
	return result, err
}

// GetClient gets a client for clientID.
func (c *ClientServiceClient) GetClient(ctx context.Context, clientID string) (*ClientGetResponse, error) {
	var result *ClientGetResponse
	path := c.Host + "/" + ClientServiceBasePath + clientID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// GetPublicClient gets a client's public client information for clientID.
func (c *ClientServiceClient) GetPublicClient(ctx context.Context, clientID string) (*ClientGetPublicResponse, error) {
	var result *ClientGetPublicResponse
	path := c.Host + "/" + ClientServiceBasePath + clientID + "/public"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) ClientServiceClient {
	authService := authClient.New(config)
	return ClientServiceClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
	}
}
