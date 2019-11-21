package storageClient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

const (
	storageServiceBasePath = "/v2/storage"
	EmailOTPQueryParam     = "email_otp"
	ToznyOTPQueryParam     = "tozny_otp"
	// The TozID JWT signed OIDC ID token issued as part of a valid TozID realm login session that contains the one time password as the `nonce` claim and TozID as the authorizing party (`azp`) claim.
	TozIDLoginTokenNonceQueryParam = "tozid_login_token_nonce"
	// The TozID realm to verify the token specified by `tozid_login_token_nonce` is signed by.
	TozIDLoginTokenRealmQueryParam = "tozid_login_token_realm"
)

//StorageClient implements an http client for communication with the metrics service.
type StorageClient struct {
	ClientID    string
	SigningKeys e3dbClients.SigningKeys
	Host        string // host will generally need to be cyclops service to get the X-Tozny-Auth header
	httpClient  *http.Client
}

func (c *StorageClient) WriteNote(ctx context.Context, params Note) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) UpsertNoteByIDString(ctx context.Context, params Note) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) ReadNote(ctx context.Context, noteID string, eacpParams map[string]string) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := request.URL.Query()
	if eacpParams != nil {
		for key, val := range eacpParams {
			urlParams.Set(key, val)
		}
	}
	urlParams.Set("note_id", noteID)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) Challenge(ctx context.Context, noteID string, params ChallengeRequest) (ChallengeResponse, error) {
	var challenges ChallengeResponse
	path := c.Host + storageServiceBasePath + "/notes/challenge"
	request, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return challenges, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("note_id", noteID)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &challenges)
	return challenges, err
}

func (c *StorageClient) Prime(ctx context.Context, noteID string, body PrimeRequestBody) (PrimeResponseBody, error) {
	path := c.Host + storageServiceBasePath + "/notes/prime"
	request, err := e3dbClients.CreateRequest("PATCH", path, body)
	var primedResponse PrimeResponseBody
	if err != nil {
		return primedResponse, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("note_id", noteID)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &primedResponse)
	return primedResponse, err
}

func (c *StorageClient) BulkDeleteByClient(ctx context.Context, clientID uuid.UUID, limit int) (BulkDeleteResponse, error) {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes/bulk/" + clientID.String()
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	var resp BulkDeleteResponse
	if err != nil {
		return resp, err
	}
	urlParams := request.URL.Query()
	if limit != 0 {
		urlParams.Set("limit", strconv.Itoa(limit))
	}
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &resp)
	return resp, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) StorageClient {
	return StorageClient{
		Host:        config.Host,
		SigningKeys: config.SigningKeys,
		ClientID:    config.ClientID,
		httpClient:  &http.Client{},
	}
}
