package storageClient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/tozny/e3db-clients-go/authClient"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

const (
	storageServiceBasePath = "/v2/storage"
	EmailOTPQueryParam     = "email_otp"
	ToznyOTPQueryParam     = "tozny_otp"
	// The TozID JWT signed OIDC ID token issued as part of a valid TozID realm login session that contains the one time password as the `nonce` claim and TozID as the authorizing party (`azp`) claim.
	TozIDLoginTokenHeader = "X-TOZID-LOGIN-TOKEN"
)

var (
	// The EACP params to set as a request
	EACPHeaders = []string{TozIDLoginTokenHeader}
)

//StorageClient implements an http client for communication with the storage service.
type StorageClient struct {
	ClientID       string
	SigningKeys    e3dbClients.SigningKeys
	EncryptionKeys e3dbClients.EncryptionKeys
	Host           string // host will generally need to be cyclops service to get the X-Tozny-Auth header
	httpClient     *http.Client
	*authClient.E3dbAuthClient
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

// CreateGroup creates a group using the specified parameters,
//returning the created group and error (if any)
func (c *StorageClient) CreateGroup(ctx context.Context, params CreateGroupRequest) (*Group, error) {
	var result *Group
	path := c.Host + storageServiceBasePath + "/groups"
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
	// Set appropriate request query params & headers for satisfying
	// a note's required EACPs
	urlParams := request.URL.Query()
	if eacpParams != nil {
		for key, val := range eacpParams {
			var isHeaderEACP bool
			for _, eacpHeader := range EACPHeaders {
				if key == eacpHeader {
					isHeaderEACP = true
					break
				}
			}
			if !isHeaderEACP {
				urlParams.Set(key, val)
			}
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

// ProxyChallengeByName allows a service to send an already authenticated request
// to the Storage service to trigger a note challenge by name.
func (c *StorageClient) ProxyChallengeByName(ctx context.Context, headers http.Header, noteName string, params ChallengeRequest) (ChallengeResponse, error) {
	var challenges ChallengeResponse
	path := c.Host + storageServiceBasePath + "/notes/challenge"
	request, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return challenges, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("id_string", noteName)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeProxiedSignedCall(ctx, headers, request, &challenges)
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

func (c *StorageClient) InternalDeleteNoteByID(ctx context.Context, noteID uuid.UUID) error {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	urlParams := request.URL.Query()
	urlParams.Set("note_id", noteID.String())
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

func (c *StorageClient) InternalDeleteNoteByName(ctx context.Context, noteName string) error {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	urlParams := request.URL.Query()
	urlParams.Set("id_string", noteName)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

// InternalSearchBySharingGroup performs an internal search to return the recordIDs for a particular sharing group.
// Sharing group defined as a subset of the access tuple: (writer_id, user_id, content_type)
// For all current uses, writer_id and user_id are the same, but must be included to take advantage of indices.
func (c *StorageClient) InternalSearchBySharingGroup(ctx context.Context, params InternalSearchBySharingTupleRequest) (*InternalSearchBySharingTupleResponse, error) {
	var result *InternalSearchBySharingTupleResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/search/sharing-group"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// OutgoingShares get outgoing shares for a given client.
func (c *StorageClient) OutgoingShares(ctx context.Context, params OutgoingShareRequest) (*OutgoingShareResponse, error) {
	var result *OutgoingShareResponse
	path := c.Host + storageServiceBasePath + "/share/outgoing"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// IncomingShares get incoming shares for a given client.
func (c *StorageClient) IncomingShares(ctx context.Context, params SearchIncomingSharesRequest) (*SearchIncomingSharesResponse, error) {
	var result *SearchIncomingSharesResponse
	path := c.Host + storageServiceBasePath + "/share/incoming"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// ProxiedAuthorization gives a list of authorizations the user has proxied out.
func (c *StorageClient) ProxiedAuthorization(ctx context.Context, params SearchAuthorizationsProxiedRequest) (*SearchAuthorizationsProxiedResponse, error) {
	var result *SearchAuthorizationsProxiedResponse
	path := c.Host + storageServiceBasePath + "/authorizer/outgoing"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GrantedAuthorizations gives a list of authorizations granted to the user.
func (c *StorageClient) GrantedAuthorizations(ctx context.Context, params SearchAuthorizedGrantedRequest) (*SearchAuthorizedGrantedResponse, error) {
	var result *SearchAuthorizedGrantedResponse
	path := c.Host + storageServiceBasePath + "/authorizer/incoming"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) WriteRecord(ctx context.Context, params Record) (*Record, error) {
	var result *Record
	path := c.Host + storageServiceBasePath + "/records"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (c *StorageClient) WriteFile(ctx context.Context, params Record) (*PendingFileResponse, error) {
	var result *PendingFileResponse
	path := c.Host + storageServiceBasePath + "/files"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

func (c *StorageClient) FileCommit(ctx context.Context, pendingFileID uuid.UUID) (*Record, error) {
	var result *Record
	path := c.Host + storageServiceBasePath + "/files/" + pendingFileID.String()
	request, err := e3dbClients.CreateRequest("PATCH", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) StorageClient {
	authService := authClient.New(config)
	return StorageClient{
		Host:           config.Host,
		SigningKeys:    config.SigningKeys,
		EncryptionKeys: config.EncryptionKeys,
		ClientID:       config.ClientID,
		httpClient:     &http.Client{},
		E3dbAuthClient: &authService,
	}
}
