package pdsClient

import (
	"context"
	"errors"
	"fmt"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

const (
	PDSServiceBasePath = "v1/storage" //HTTP PATH prefix for calls to the Personal Data Storage service
)

//E3dbPDSClient implements an http client for communication with an e3db PDS service.
type E3dbPDSClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

// readPolicy wraps an e3db API object
// for granting read access to records
type readPolicy struct {
	Read map[string]interface{} `json:"read"`
}

// authorizePolicy wraps an e3db API object
// for granting share access for records of a given type
type authorizePolicy struct {
	Authorize map[string]interface{} `json:"authorizer"`
}

// allowReadPolicy wraps an e3db API object granting read access to records
type allowReadPolicy struct {
	Allow []readPolicy `json:"allow"`
}

// allowAuthorizerPolicy wraps an e3db API object granting authorization to share
// records of a specified type on behalf of the granting client
type allowAuthorizerPolicy struct {
	Allow []authorizePolicy `json:"allow"`
}

// AddAuthorizedSharer attempts to authorize another e3db client to share
// records of the specified record type, returning error (if any).
func (c *E3dbPDSClient) AddAuthorizedSharer(ctx context.Context, params AddAuthorizedWriterRequest) error {
	err := c.CreateSharingAccessKey(ctx, CreateSharingAccessKeyRequest{
		UserID:     params.UserID,
		WriterID:   params.WriterID,
		ReaderID:   params.AuthorizerID,
		RecordType: params.RecordType})
	if err != nil {
		return err
	}
	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.AuthorizerID + "/" + params.RecordType
	// Create a policy to apply for the authorizer to be allowed to share records of type specified in params
	authorizerPolicy := allowAuthorizerPolicy{
		Allow: []authorizePolicy{
			authorizePolicy{
				Authorize: make(map[string]interface{}),
			},
		},
	}
	request, internalError := e3dbClients.CreateRequest("PUT", path, authorizerPolicy)
	if internalError != nil {
		err = e3dbClients.FlatMapInternalError(*internalError)
	}
	if err != nil {
		return err
	}
	internalError = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// Share attempts to grants another e3db client permission to read records of the
// specified record type, returning error (if any).
func (c *E3dbPDSClient) ShareRecords(ctx context.Context, params ShareRecordsRequest) error {
	err := c.CreateSharingAccessKey(ctx, CreateSharingAccessKeyRequest{
		UserID:     params.UserID,
		WriterID:   params.WriterID,
		ReaderID:   params.ReaderID,
		RecordType: params.RecordType})
	if err != nil {
		return err
	}
	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.ReaderID + "/" + params.RecordType
	// Create a policy to apply for the reader to be allowed to read records of type specified in params
	sharePolicy := allowReadPolicy{
		Allow: []readPolicy{
			readPolicy{
				Read: make(map[string]interface{}),
			},
		},
	}
	request, internalError := e3dbClients.CreateRequest("PUT", path, sharePolicy)
	if internalError != nil {
		err = e3dbClients.FlatMapInternalError(*internalError)
	}
	if err != nil {
		return err
	}
	internalError = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// AuthorizerShareRecords attempts to grants another e3db client permission to read records of the
// specified record type the authorizer is authorized to share , returning error (if any).
func (c *E3dbPDSClient) AuthorizerShareRecords(ctx context.Context, params AuthorizerShareRecordsRequest) error {
	err := c.CreateAuthorizerSharingAccessKey(ctx, CreateAuthorizerSharingAccessKeyRequest{
		UserID:       params.UserID,
		WriterID:     params.WriterID,
		ReaderID:     params.ReaderID,
		AuthorizerID: params.AuthorizerID,
		RecordType:   params.RecordType})
	if err != nil {
		return err
	}
	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.ReaderID + "/" + params.RecordType
	// Create a policy to apply for the reader to be allowed to read records of type specified in params
	sharePolicy := allowReadPolicy{
		Allow: []readPolicy{
			readPolicy{
				Read: make(map[string]interface{}),
			},
		},
	}
	request, internalError := e3dbClients.CreateRequest("PUT", path, sharePolicy)
	if internalError != nil {
		err = e3dbClients.FlatMapInternalError(*internalError)
	}
	if err != nil {
		return err
	}
	internalError = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// InternalAllowedReads attempts to retrieve the list of AllowedRead policies for other users records for the given reader using an internal only e3db endpoint, returning InternalAllowedReadsResponse(which may or may not be empty of AllowedRead policies) and error (if any).
func (c *E3dbPDSClient) InternalAllowedReads(ctx context.Context, readerID string) (*InternalAllowedReadsResponse, error) {
	var result *InternalAllowedReadsResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_reads/" + readerID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// InternalAllowedReadsForAccessPolicy attempts to retrieve the list of allowed readers given an access policy.
func (c *E3dbPDSClient) InternalAllowedReadsForAccessPolicy(ctx context.Context, params InternalAllowedReadersForPolicyRequest) (*InternalAllowedReadersForPolicyResponse, error) {
	var result *InternalAllowedReadersForPolicyResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_readers"
	request, internalError := e3dbClients.CreateRequest("POST", path, params)
	if internalError != nil {
		return result, e3dbClients.FlatMapInternalError(*internalError)
	}
	internalError = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// InternalRegisterClient uses an internal(available only to locally running e3db instances) endpoint to register a client, returning the registered client and error (if any).
func (c *E3dbPDSClient) InternalRegisterClient(ctx context.Context, params RegisterClientRequest) (*RegisterClientResponse, error) {
	var result *RegisterClientResponse
	path := c.Host + "/" + PDSServiceBasePath + "/clients"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// InternalSearch returns records macthing the provided params,
// returning the list of records and error (if any).
func (c *E3dbPDSClient) InternalSearch(ctx context.Context, params InternalSearchRequest) (*InternalSearchResponse, error) {
	var result *InternalSearchResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/search"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// InternalSearchAllowedReads returns the allowed reads that match the
// provided params, returning a paginated list of allowed reads and error (if any).
func (c *E3dbPDSClient) InternalSearchAllowedReads(ctx context.Context, params InternalSearchAllowedReadsRequest) (*InternalSearchAllowedReadsResponse, error) {
	var result *InternalSearchAllowedReadsResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_reads"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// PutAccessKey attempts to set an access key that E3DB will enforce be used to write records of the specified type for the specified user, client, and writer, returning the response and error (if any).
func (c *E3dbPDSClient) PutAccessKey(ctx context.Context, params PutAccessKeyRequest) (*PutAccessKeyResponse, error) {
	var result *PutAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	request, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// GetAccessKey attempts to get an access key stored in E3DB returning the response and error (if any).
func (c *E3dbPDSClient) GetAccessKey(ctx context.Context, params GetAccessKeyRequest) (*GetAccessKeyResponse, error) {
	var result *GetAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// WriteRecord attempts to store a record in e3db, returning stored record and error (if any).
// XXX: Data is not encrypted in this method, it is the caller's responsibility to ensure data is encrypted before sending to e3db.
func (c *E3dbPDSClient) WriteRecord(ctx context.Context, params WriteRecordRequest) (*WriteRecordResponse, error) {
	var result *WriteRecordResponse
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// DeleteRecord attempts to delete a record in e3db, returning error (if any).
func (c *E3dbPDSClient) DeleteRecord(ctx context.Context, params DeleteRecordRequest) error {
	path := c.Host + "/" + PDSServiceBasePath + "/records/" + params.RecordID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// ListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ListRecords(ctx context.Context, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// ProxyListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ProxyListRecords(ctx context.Context, authToken string, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeProxiedUserCall(ctx, authToken, request, &result)
	return result, e3dbClients.FlatMapInternalError(internalError)
}

// BatchGetRecords makes a call to batch get the records in params,
// returning the records (if they exist) and error (if any).
func (c *E3dbPDSClient) BatchGetRecords(ctx context.Context, params BatchGetRecordsRequest) (*BatchGetRecordsResult, error) {
	var result *BatchGetRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// BatchGetRecords makes a call to batch get the records in params,
// on behalf of the user with the specified authToken,
// returning the records (if they exist) and error (if any).
func (c *E3dbPDSClient) ProxyBatchGetRecords(ctx context.Context, authToken string, params BatchGetRecordsRequest) (*BatchGetRecordsResult, error) {
	var result *BatchGetRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	request, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeProxiedUserCall(ctx, authToken, request, &result)
	return result, e3dbClients.FlatMapInternalError(internalError)
}

// InternalGetRecord attempts to get a record using an internal only e3db endpoint, returning fetched record and error (if any).
func (c *E3dbPDSClient) InternalGetRecord(ctx context.Context, recordID string) (*InternalGetRecordResponse, error) {
	var result *InternalGetRecordResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/records/" + recordID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, e3dbClients.FlatMapInternalError(*internalError)
}

// HealthCheck checks whether the storage service is up,
// returning error if unable to connect to the search service.
func (c *E3dbPDSClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + PDSServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	internalError := e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return e3dbClients.FlatMapInternalError(*internalError)
}

// CreateSharingAccessKey attempts to create an access key for the specified reader to be able to decrypt records of the specified type, returning error (if any).
func (c *E3dbPDSClient) CreateSharingAccessKey(ctx context.Context, params CreateSharingAccessKeyRequest) error {
	// Get the current encrypted access key
	// used to write records of this type by
	// the client specified in params
	getAccessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.UserID,
		RecordType: params.RecordType,
	})
	if err != nil {
		return err
	}
	encryptedAccessKey := getAccessKeyResponse.EAK
	if encryptedAccessKey == "" {
		return errors.New(fmt.Sprintf("no access key exists for records of type %s", params.RecordType))
	}
	// TODO: Decrypt this key
	// TODO: using the decrypted version of
	// encryptedAccessKey and the public key of
	// the reader specified in params,
	// create an encrypted access key that
	// the reader can decrypt
	// Put the encrypted access key for the reader
	_, err = c.PutAccessKey(ctx, PutAccessKeyRequest{
		UserID:             params.UserID,
		WriterID:           params.WriterID,
		ReaderID:           params.ReaderID,
		RecordType:         params.RecordType,
		EncryptedAccessKey: encryptedAccessKey,
	})
	return err
}

// CreateAuthorizerSharingAccessKey attempts to create an access key for the specified reader to be able to decrypt records of the specified type that the authorizer is authorized to share, returning error (if any).
func (c *E3dbPDSClient) CreateAuthorizerSharingAccessKey(ctx context.Context, params CreateAuthorizerSharingAccessKeyRequest) error {
	// Get the current encrypted access key
	// used to write records of this type by
	// the client specified in params
	getAccessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.AuthorizerID,
		RecordType: params.RecordType,
	})
	if err != nil {
		return err
	}
	encryptedAccessKey := getAccessKeyResponse.EAK
	if encryptedAccessKey == "" {
		return errors.New(fmt.Sprintf("no access key exists for records of type %s", params.RecordType))
	}
	// TODO: Decrypt this key
	// TODO: using the decrypted version of
	// encryptedAccessKey and the public key of
	// the reader specified in params,
	// create an encrypted access key that
	// the reader can decrypt
	// Put the encrypted access key for the authorizer
	_, err = c.PutAccessKey(ctx, PutAccessKeyRequest{
		UserID:             params.UserID,
		WriterID:           params.WriterID,
		ReaderID:           params.ReaderID,
		RecordType:         params.RecordType,
		EncryptedAccessKey: encryptedAccessKey,
	})
	return err
}

// New returns a new E3dbPDSClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbPDSClient {
	authService := authClient.New(config)
	return E3dbPDSClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
	}
}
