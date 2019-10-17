package clientServiceClient

import (
	"context"
	"strconv"

	e3dbClients "github.com/tozny/e3db-clients-go"
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
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("next", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("limit", strconv.Itoa(int(params.Limit)))
	request.URL.RawQuery = urlParams.Encode()
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

// AdminGet makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminDelete(ctx context.Context, clientID string) error {
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + clientID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

// AdminToggleClientEnabled enables/disables clients with account auth.
func (c *ClientServiceClient) AdminToggleClientEnabled(ctx context.Context, params AdminToggleClientEnabledRequest) error {
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + params.ClientID + "/enable"
	request, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
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

// BatchPublicInfo makes POST call to retrieve a list of clients public information for clientIDs
func (c *ClientServiceClient) BatchPublicInfo(ctx context.Context, params ClientBatchPublicInfoRequest) (*ClientBatchPublicInfoResponse, error) {
	var result *ClientBatchPublicInfoResponse
	path := c.Host + "/" + ClientServiceBasePath + "public"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// InternalPatchBackup calls internal endpoint to flip a clients has backup flag.
func (c *ClientServiceClient) InternalPatchBackup(ctx context.Context, params InternalClientPatchBackupRequest) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/backup"
	request, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

// InternalClientInfoForSignature calls internal endpoint to authenticate for clientID and publicKey.
func (c *ClientServiceClient) InternalClientInfoForSignature(ctx context.Context, params ClientInfoForSignatureRequest) (*e3dbClients.ToznyAuthenticatedClientContext, error) {
	var result *e3dbClients.ToznyAuthenticatedClientContext
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/signature-context"
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	query := request.URL.Query()
	query.Add("public_key", params.PublicKey)
	request.URL.RawQuery = query.Encode()
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// InternalClientInfoForTokenClaims calls internal endpoint to authenticate for a clientID.
func (c *ClientServiceClient) InternalClientInfoForTokenClaims(ctx context.Context, params ClientInfoForTokenClaimsRequest) (*e3dbClients.ToznyAuthenticatedClientContext, error) {
	var result *e3dbClients.ToznyAuthenticatedClientContext
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/token-context"
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err

}

// InternalAccountIDForClientID calls internal endpoint to return account id associated with a client id.
func (c *ClientServiceClient) InternalAccountIDForClientID(ctx context.Context, clientID string) (*InternalAccountIDForClientIDResponse, error) {
	var result *InternalAccountIDForClientIDResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + clientID + "/accountid"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// AdminToggleClientEnabled enables/disables clients with account auth.
func (c *ClientServiceClient) InternalToggleClientEnabled(ctx context.Context, params InternalToggleEnabledRequest) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/enable"
	request, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

func (c *ClientServiceClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + ClientServiceBasePath + "healthcheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakePublicCall(ctx, request, nil)
	return err
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
