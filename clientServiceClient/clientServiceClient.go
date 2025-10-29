package clientServiceClient

import (
	"context"
	"net/http"
	"strconv"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

var (
	ClientServiceBasePath = "v1/client/"
)

// ClientServiceClient implements an http client for communication with the client service.
type ClientServiceClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
	requester request.Requester
}

// AdminList makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminList(ctx context.Context, params AdminListRequest) (*AdminListResponse, error) {
	var result *AdminListResponse
	path := c.Host + "/" + ClientServiceBasePath + "admin"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("next", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("limit", strconv.Itoa(int(params.Limit)))
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// AdminGet makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminGet(ctx context.Context, clientID string) (*AdminGetResponse, error) {
	var result *AdminGetResponse
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + clientID
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// AdminGet makes authenticated call to the /admin endpoint for client service.
func (c *ClientServiceClient) AdminDelete(ctx context.Context, clientID string) error {
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + clientID
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// AdminToggleClientEnabled enables/disables clients with account auth.
func (c *ClientServiceClient) AdminToggleClientEnabled(ctx context.Context, params AdminToggleClientEnabledRequest) error {
	path := c.Host + "/" + ClientServiceBasePath + "admin/" + params.ClientID + "/enable"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InternalDeleteClient makes authenticated call to the /internal endpoint for client service.
func (c *ClientServiceClient) InternalDeleteClient(ctx context.Context, realmName string, clientID string) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + "realm/" + realmName + "/client/" + clientID
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InternalUpdateClientDelete makes authenticated call to the /internal endpoint for client service.
func (c *ClientServiceClient) InternalUpdateClientDelete(ctx context.Context, clientID string) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + "clients/" + clientID + "/delete"
	req, err := e3dbClients.CreateRequest("PUT", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// Register registers a client.
func (c *ClientServiceClient) Register(ctx context.Context, params ClientRegisterRequest) (*ClientRegisterResponse, error) {
	var result *ClientRegisterResponse
	path := c.Host + "/" + "v1/account/e3db/clients/register"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakePublicCall(ctx, c.requester, req, &result)
	return result, err
}

// InternalRegister registers a client returning details about the registered client and error (if any).
func (c *ClientServiceClient) InternalRegister(ctx context.Context, params ClientRegisterRequest) (*ClientRegisterResponse, error) {
	var result *ClientRegisterResponse
	path := c.Host + "/" + ClientServiceBasePath
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakePublicCall(ctx, c.requester, req, &result)
	return result, err
}

// BackfillClientSigningKeys assigns signing keys to clients with none set
func (c *ClientServiceClient) BackfillClientSigningKeys(ctx context.Context, params BackfillClientSigningKeysRequest) (*Client, error) {
	var result *Client
	path := c.Host + "/" + ClientServiceBasePath + params.ClientID.String() + "/keys"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// GetClient gets a client for clientID.
func (c *ClientServiceClient) GetClient(ctx context.Context, clientID string) (*ClientGetResponse, error) {
	var result *ClientGetResponse
	path := c.Host + "/" + ClientServiceBasePath + clientID
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// GetPublicClient gets a client's public client information for clientID.
func (c *ClientServiceClient) GetPublicClient(ctx context.Context, clientID string) (*ClientGetPublicResponse, error) {
	var result *ClientGetPublicResponse
	path := c.Host + "/" + ClientServiceBasePath + clientID + "/public"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// BatchPublicInfo makes POST call to retrieve a list of clients public information for clientIDs
func (c *ClientServiceClient) BatchPublicInfo(ctx context.Context, params ClientBatchPublicInfoRequest) (*ClientBatchPublicInfoResponse, error) {
	var result *ClientBatchPublicInfoResponse
	path := c.Host + "/" + ClientServiceBasePath + "public"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalPatchBackup calls internal endpoint to flip a clients has backup flag.
func (c *ClientServiceClient) InternalPatchBackup(ctx context.Context, params InternalClientPatchBackupRequest) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/backup"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InternalClientInfoForSignature calls internal endpoint to authenticate for clientID and publicKey.
func (c *ClientServiceClient) InternalClientInfoForSignature(ctx context.Context, params ClientInfoForSignatureRequest) (*e3dbClients.ToznyAuthenticatedClientContext, error) {
	var result *e3dbClients.ToznyAuthenticatedClientContext
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/signature-context"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	query := req.URL.Query()
	query.Add("public_key", params.PublicKey)
	req.URL.RawQuery = query.Encode()
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalClientInfoForTokenClaims calls internal endpoint to authenticate for a clientID.
func (c *ClientServiceClient) InternalClientInfoForTokenClaims(ctx context.Context, params ClientInfoForTokenClaimsRequest) (*e3dbClients.ToznyAuthenticatedClientContext, error) {
	var result *e3dbClients.ToznyAuthenticatedClientContext
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/token-context"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err

}

// InternalAccountIDForClientID calls internal endpoint to return account id associated with a client id.
func (c *ClientServiceClient) InternalAccountIDForClientID(ctx context.Context, clientID string) (*InternalAccountIDForClientIDResponse, error) {
	var result *InternalAccountIDForClientIDResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + clientID + "/accountid"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalClientList calls internal endpoint to return all client ID's. This endpoint is paginated.
// The last page will containe a next token equal to 0
func (c *ClientServiceClient) InternalClientList(ctx context.Context, params InternalClientListRequest) (*InternalClientListResponse, error) {
	var result *InternalClientListResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + "clients"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("next", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("limit", strconv.Itoa(int(params.Limit)))
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalClientInfoList calls internal endpoint to return all clients with status. This endpoint is paginated.
// The last page will containe a next token equal to 0
func (c *ClientServiceClient) InternalClientInfoList(ctx context.Context, params InternalClientListRequest) (*InternalClientInfoListResponse, error) {
	var result *InternalClientInfoListResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + "clients/info"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("next", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("limit", strconv.Itoa(int(params.Limit)))
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// AdminToggleClientEnabled enables/disables clients with account auth.
func (c *ClientServiceClient) InternalToggleClientEnabled(ctx context.Context, params InternalToggleEnabledRequest) error {
	path := c.Host + "/internal/" + ClientServiceBasePath + params.ClientID + "/enable"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InternalRollQueenClient rolls the queen client with a new backup client.
func (c *ClientServiceClient) InternalRollQueenClient(ctx context.Context, params InternalRollQueenClientRequest) (*ClientRegisterResponse, error) {
	var result *ClientRegisterResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + "queen"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (c *ClientServiceClient) EmailChallenge(ctx context.Context, params IssueEmailChallengeRequest) (*IssueEmailChallengeResponse, error) {
	var result *IssueEmailChallengeResponse
	path := c.Host + "/internal/" + ClientServiceBasePath + "challenge/email"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (c *ClientServiceClient) VerifyEmailChallenge(ctx context.Context, params VerifyEmailChallengeRequest) (*OtpData, error) {
	var result *OtpData
	path := c.Host + "/internal/" + ClientServiceBasePath + "challenge/email"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (c *ClientServiceClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + ClientServiceBasePath + "healthcheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakePublicCall(ctx, c.requester, req, nil)
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
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
