package pdsClient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/clientServiceClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	PDSServiceBasePath = "v1/storage" //HTTP PATH prefix for calls to the Personal Data Storage service
)

//E3dbPDSClient implements an http client for communication with an e3db PDS service.
type E3dbPDSClient struct {
	ClientID       string
	APIKey         string
	APISecret      string
	Host           string
	EncryptionKeys e3dbClients.EncryptionKeys // AsymmetricEncryptionKeypair used for encrypting and decrypting data
	*authClient.E3dbAuthClient
	requester request.Requester
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

// denyReadPolicy wraps an e3db API object denying read access to records
type denyReadPolicy struct {
	Deny []readPolicy `json:"deny"`
}

// allowAuthorizerPolicy wraps an e3db API object granting authorization to share
// records of a specified type on behalf of the granting client
type allowAuthorizerPolicy struct {
	Allow []authorizePolicy `json:"allow"`
}

// denyAuthorizerPolicy wraps an e3db API object revoking authorization to share
// records of a specified type on behalf of the granting client
type denyAuthorizerPolicy struct {
	Deny []authorizePolicy `json:"deny"`
}

// ClientInfo fetches the public information about a TozStore client based on ID. This requires
// A valid auth token, so API Key and Secret must be available
func (c *E3dbPDSClient) ClientInfo(ctx context.Context, clientID string) (*ClientInfo, error) {
	var result *ClientInfo
	path := fmt.Sprintf("%s/%s/clients/%s", c.Host, PDSServiceBasePath, url.QueryEscape(clientID))
	req, err := e3dbClients.CreateRequest(http.MethodGet, path, nil)
	if err != nil {
		return result, err
	}

	e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, nil
}

// FileCommit finalized a pending file write, returning the committed file record
// or error (if any)
func (c *E3dbPDSClient) FileCommit(ctx context.Context, pendingFileID string) (*WriteRecordResponse, error) {
	var result *WriteRecordResponse
	path := c.Host + "/" + PDSServiceBasePath + "/files/" + pendingFileID
	req, err := e3dbClients.CreateRequest("PATCH", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
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
			{
				Authorize: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, authorizerPolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// RemoveAuthorizedSharer attempts to remove another e3db clients ability to share
// records of the specified record type, returning error (if any).
func (c *E3dbPDSClient) RemoveAuthorizedSharer(ctx context.Context, params AddAuthorizedWriterRequest) error {
	err := c.DeleteAccessKey(ctx, DeleteAccessKeyRequest{
		UserID:     params.UserID,
		WriterID:   params.WriterID,
		ReaderID:   params.AuthorizerID,
		RecordType: params.RecordType})

	if err != nil {
		return err
	}

	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.AuthorizerID + "/" + params.RecordType
	// Create a policy to apply for the authorizer to be denied sharing records of type specified in params
	authorizerPolicy := denyAuthorizerPolicy{
		Deny: []authorizePolicy{
			{
				Authorize: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, authorizerPolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
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
			{
				Read: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, sharePolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// UnshareRecords revokes another Tozny's client permission to read records of the
// specified record type, returning error (if any).
func (c *E3dbPDSClient) UnshareRecords(ctx context.Context, params ShareRecordsRequest) error {
	err := c.DeleteAccessKey(ctx, DeleteAccessKeyRequest{
		UserID:     params.UserID,
		WriterID:   params.WriterID,
		ReaderID:   params.ReaderID,
		RecordType: params.RecordType})
	if err != nil {
		return err
	}
	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.ReaderID + "/" + params.RecordType
	// Create a policy to apply for the reader to be denied to read records of type specified in params
	sharePolicy := denyReadPolicy{
		Deny: []readPolicy{
			{
				Read: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, sharePolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// AuthorizerShareRecords attempts to grants another e3db client permission to read records of the
// specified record type the authorizer is authorized to share, returning error (if any).
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
			{
				Read: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, sharePolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// AuthorizerUnshareRecords unshares the specified record type with the specified reader on behalf of
// the authorizer, returning error (if any).
func (c *E3dbPDSClient) AuthorizerUnshareRecords(ctx context.Context, params AuthorizerUnshareRecordsRequest) error {
	// Delete the access key that gave the reader cryptographic access for records of this type
	deleteAccessKeyParams := DeleteAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.ReaderID,
		RecordType: params.RecordType,
	}
	err := c.DeleteAccessKey(ctx, deleteAccessKeyParams)
	if err != nil {
		return err
	}
	// Update the policy access for this reader to deny the reader retrieving records of this type
	path := c.Host + "/" + PDSServiceBasePath + "/policy/" + params.UserID + "/" + params.WriterID + "/" + params.ReaderID + "/" + params.RecordType
	// Create a policy to apply for the reader to be allowed to read records of type specified in params
	unsharePolicy := denyReadPolicy{
		Deny: []readPolicy{
			{
				Read: make(map[string]interface{}),
			},
		},
	}
	req, err := e3dbClients.CreateRequest("PUT", path, unsharePolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// InternalAllowedReads attempts to retrieve the list of AllowedRead policies for other users records for the given reader using an internal only e3db endpoint, returning InternalAllowedReadsResponse(which may or may not be empty of AllowedRead policies) and error (if any).
func (c *E3dbPDSClient) InternalAllowedReads(ctx context.Context, readerID string) (*InternalAllowedReadsResponse, error) {
	var result *InternalAllowedReadsResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_reads/" + readerID
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalAllowedReadsForAccessPolicy attempts to retrieve the list of allowed readers given an access policy.
func (c *E3dbPDSClient) InternalAllowedReadsForAccessPolicy(ctx context.Context, params InternalAllowedReadersForPolicyRequest) (*InternalAllowedReadersForPolicyResponse, error) {
	var result *InternalAllowedReadersForPolicyResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_readers"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalSearch returns records matching the provided params,
// returning the list of records and error (if any).
func (c *E3dbPDSClient) InternalSearch(ctx context.Context, params InternalSearchRequest) (*InternalSearchResponse, error) {
	var result *InternalSearchResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/search"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalSearchAllowedReads returns the allowed reads that match the
// provided params, returning a paginated list of allowed reads and error (if any).
func (c *E3dbPDSClient) InternalSearchAllowedReads(ctx context.Context, params InternalSearchAllowedReadsRequest) (*InternalSearchAllowedReadsResponse, error) {
	var result *InternalSearchAllowedReadsResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_reads"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// InternalBulkDelete deletes up to limit number of records for the given client. This endpoint is bootstrap protected
func (c *E3dbPDSClient) InternalBulkDelete(ctx context.Context, clientID uuid.UUID, limit int) (BulkDeleteResponse, error) {
	var result BulkDeleteResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/records/bulk/" + clientID.String()
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	if limit != 0 {
		urlParams.Set("limit", strconv.Itoa(limit))
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// PutAccessKey attempts to set an access key that E3DB will enforce be used to write records of the specified type for the specified user, client, and writer, returning the response and error (if any).
func (c *E3dbPDSClient) PutAccessKey(ctx context.Context, params PutAccessKeyRequest) (*PutAccessKeyResponse, error) {
	var result *PutAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// PutEncryptedAccessKey wraps PutAccessKey to encrypt an un-encryptedAK before placing it in TozStore.
func (c *E3dbPDSClient) PutEncryptedAccessKey(ctx context.Context, params PutAccessKeyRequest, unencryptedAK e3dbClients.SymmetricKey) (*PutAccessKeyResponse, error) {
	eak, err := e3dbClients.EncryptAccessKey(unencryptedAK, c.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	params.EncryptedAccessKey = eak
	return c.PutAccessKey(ctx, params)
}

// GetAccessKey attempts to get an access key stored in E3DB returning the response and error (if any).
func (c *E3dbPDSClient) GetAccessKey(ctx context.Context, params GetAccessKeyRequest) (*GetAccessKeyResponse, error) {
	var result *GetAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// DeleteAccessKey attempts to delete an access key stored in E3DB returning the response and error (if any).
func (c *E3dbPDSClient) DeleteAccessKey(ctx context.Context, params DeleteAccessKeyRequest) error {
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

func (c *E3dbPDSClient) EncryptRecord(ctx context.Context, record Record) (Record, error) {
	// Get an access key
	accessKey, err := c.GetOrCreateAccessKey(ctx, GetOrCreateAccessKeyRequest{
		WriterID:   record.Metadata.WriterID,
		UserID:     record.Metadata.UserID,
		ReaderID:   record.Metadata.UserID,
		RecordType: record.Metadata.Type})
	if err != nil {
		return record, err
	}
	// Encrypt the record
	encryptedData := e3dbClients.EncryptData(record.Data, accessKey)
	// Return the encrypted record
	record.Data = *encryptedData
	return record, err
}

// WriteRecord locally encrypts and stores a record in e3db, returning stored record and error (if any).
func (c *E3dbPDSClient) WriteRecord(ctx context.Context, params WriteRecordRequest) (*WriteRecordResponse, error) {
	var result *WriteRecordResponse
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (c *E3dbPDSClient) DecryptRecord(ctx context.Context, record Record) (Record, error) {
	// Get an encrypted access key
	accessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   record.Metadata.WriterID,
		UserID:     record.Metadata.UserID,
		ReaderID:   c.ClientID,
		RecordType: record.Metadata.Type})
	if err != nil {
		return record, err
	}
	// Decrypt the access key
	encryptedAccessKey := accessKeyResponse.EAK
	if encryptedAccessKey == "" {
		return record, errors.New(fmt.Sprintf("no access key exists for records of type %s", record.Metadata.Type))
	}
	// otherwise attempt to decrypt the returned access key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return record, err
	}
	accessKey, err := e3dbClients.DecryptEAK(encryptedAccessKey, accessKeyResponse.AuthorizerPublicKey.Curve25519, rawEncryptionKey)
	if err != nil {
		return record, err
	}
	// Decrypt the record
	decrypted, err := e3dbClients.DecryptData(record.Data, accessKey)
	if err != nil {
		return record, err
	}
	// Return the decrypted record
	record.Data = *decrypted
	return record, err
}

// DecryptGroupRecordWithGroupEncryptedAccessKey takes a record and an eak response, decrypts the membership key used for encrypting the record, and the public key
// for the writer of the record. Then decrypts the record and returns data
func (c *E3dbPDSClient) DecryptGroupRecordWithGroupEncryptedAccessKey(ctx context.Context, record Record, groupEncryptedAccessKey *GetEAKResponse) (Record, error) {
	// Decrypt the access key
	encryptedAccessKey := groupEncryptedAccessKey.EAK
	if encryptedAccessKey == "" {
		return record, fmt.Errorf("no access key exists for records of type %s", record.Metadata.Type)
	}
	// otherwise attempt to decrypt the returned access key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return record, err
	}
	// Right now we only have one Wrapper, So this should return the Group Key
	var rawGroupPrivateKey e3dbClients.SymmetricKey
	var writerPublicKey string
	for _, wrapper := range *groupEncryptedAccessKey.AccessKeyWrappers {
		rawGroupPrivateKey, err = e3dbClients.DecryptEAK(wrapper.MembershipKey, groupEncryptedAccessKey.AuthorizerPublicKey.Curve25519, rawEncryptionKey)
		if err != nil {
			return record, err
		}
		writerPublicKey = wrapper.PublicKey
	}
	accessKey, err := e3dbClients.DecryptEAK(encryptedAccessKey, writerPublicKey, rawGroupPrivateKey)
	if err != nil {
		return record, err
	}
	// Decrypt the record
	decrypted, err := e3dbClients.DecryptData(record.Data, accessKey)
	if err != nil {
		return record, err
	}
	// Return the decrypted record
	record.Data = *decrypted
	return record, err
}

// DeleteRecord attempts to delete a record in e3db, returning error (if any).
func (c *E3dbPDSClient) DeleteRecord(ctx context.Context, params DeleteRecordRequest) error {
	path := c.Host + "/" + PDSServiceBasePath + "/records/" + params.RecordID
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// ListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ListRecords(ctx context.Context, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// ProxyListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ProxyListRecords(ctx context.Context, authToken string, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeProxiedUserCall(ctx, c.requester, authToken, req, &result)
	return result, err
}

// BatchGetRecords makes a call to batch get the records in params,
// returning the records (if they exist) and error (if any).
func (c *E3dbPDSClient) BatchGetRecords(ctx context.Context, params BatchGetRecordsRequest) (*BatchGetRecordsResult, error) {
	var result *BatchGetRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// BatchGetRecords makes a call to batch get the records in params,
// on behalf of the user with the specified authToken,
// returning the records (if they exist) and error (if any).
func (c *E3dbPDSClient) ProxyBatchGetRecords(ctx context.Context, authToken string, params BatchGetRecordsRequest) (*BatchGetRecordsResult, error) {
	var result *BatchGetRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeProxiedUserCall(ctx, c.requester, authToken, req, &result)
	return result, err
}

// InternalGetRecord attempts to get a record using an internal only e3db endpoint, returning fetched record and error (if any).
func (c *E3dbPDSClient) InternalGetRecord(ctx context.Context, recordID string) (*InternalGetRecordResponse, error) {
	var result *InternalGetRecordResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/records/" + recordID
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// HealthCheck checks whether the storage service is up,
// returning error if unable to connect to the search service.
func (c *E3dbPDSClient) HealthCheck(ctx context.Context) error {
	path := c.Host + "/" + PDSServiceBasePath + "/servicecheck"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
	return err
}

// CreateSharingAccessKey attempts to create an access key for the specified reader to be able to decrypt records of the specified type, returning error (if any).
func (c *E3dbPDSClient) CreateSharingAccessKey(ctx context.Context, params CreateSharingAccessKeyRequest) error {
	// Get the current encrypted access key
	// used to write records of this type by
	// the client specified in params
	accessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.UserID,
		RecordType: params.RecordType,
	})
	if err != nil {
		return err
	}
	// Decrypt the access key
	encryptedAccessKey := accessKeyResponse.EAK
	if encryptedAccessKey == "" {
		return errors.New(fmt.Sprintf("no access key exists for records of type %s", params.RecordType))
	}
	return c.CreateSharedAccessKey(ctx, CreateSharedAccessKeyRequest{
		WriterID:           params.WriterID,
		UserID:             params.UserID,
		ReaderID:           params.ReaderID,
		RecordType:         params.RecordType,
		EncryptedAccessKey: encryptedAccessKey,
		ShareePublicKey:    accessKeyResponse.AuthorizerPublicKey.Curve25519,
	})
}

// CreateAuthorizerSharingAccessKey attempts to create an access key for the specified reader to be able to decrypt records of the specified type that the authorizer is authorized to share, returning error (if any).
func (c *E3dbPDSClient) CreateAuthorizerSharingAccessKey(ctx context.Context, params CreateAuthorizerSharingAccessKeyRequest) error {
	// Get the current encrypted access key
	// used to write records of this type by
	// the client specified in params
	accessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.AuthorizerID,
		RecordType: params.RecordType,
	})
	if err != nil {
		return err
	}
	encryptedAccessKey := accessKeyResponse.EAK
	if encryptedAccessKey == "" {
		return errors.New(fmt.Sprintf("no access key exists for records of type %s", params.RecordType))
	}
	return c.CreateSharedAccessKey(ctx, CreateSharedAccessKeyRequest{
		WriterID:           params.WriterID,
		UserID:             params.UserID,
		ReaderID:           params.ReaderID,
		RecordType:         params.RecordType,
		EncryptedAccessKey: encryptedAccessKey,
		ShareePublicKey:    accessKeyResponse.AuthorizerPublicKey.Curve25519,
	})
}

// CreateSharedAccessKey creates an encrypted (using the sharee's public key) version of the provided access key for
// the specified sharee/readerID, storing the version of the access key that the reader can decrypt
// with TozStore to allow the reader to fetch and use the key, returning error (if any).
// The SharedAccessKey will be created idempotently (if it exists no error will be returned)
func (c *E3dbPDSClient) CreateSharedAccessKey(ctx context.Context, params CreateSharedAccessKeyRequest) error {
	// Decrypt the access key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return err
	}
	accessKey, err := e3dbClients.DecryptEAK(params.EncryptedAccessKey, params.ShareePublicKey, rawEncryptionKey)
	if err != nil {
		return err
	}
	// Using the decrypted version of
	// encryptedAccessKey and the public key of
	// the reader specified in params,
	// create an encrypted access key that
	// the reader can decrypt
	wrappedEncryptedAccessKey, err := c.WrapAccessKeyForReader(ctx, accessKey, params.ReaderID)
	// Put the encrypted access key for the reader
	_, err = c.PutAccessKey(ctx, PutAccessKeyRequest{
		WriterID:           params.WriterID,
		UserID:             params.UserID,
		ReaderID:           params.ReaderID,
		RecordType:         params.RecordType,
		EncryptedAccessKey: wrappedEncryptedAccessKey,
	})
	// Check to see if the error was 409 / key already exists
	if err != nil {
		tozError, ok := err.(*e3dbClients.RequestError)
		if !ok {
			return err
		}
		// If error was not 409 , return the error
		if tozError.StatusCode != http.StatusConflict {
			return err
		}
		// Otherwise continue as 409 is expected if the key has already been created
	}
	return nil
}

// WrapAccessKeyForReader wraps an access key for reading records of a type in a layer of encryption
// that the specified reader will be able to unwrap and use to read records of that type, returning the
// wrapped access key and error (if any).
func (c *E3dbPDSClient) WrapAccessKeyForReader(ctx context.Context, accessKey e3dbClients.SymmetricKey, readerID string) (string, error) {
	var wrappedAccessKey string
	clientServiceConfig := e3dbClients.ClientConfig{
		APIKey:    c.APIKey,
		APISecret: c.APISecret,
		Host:      c.Host,
		AuthNHost: c.Host,
	}
	clientClient := clientServiceClient.New(clientServiceConfig)
	publicClient, err := clientClient.GetPublicClient(ctx, readerID)
	if err != nil {
		return wrappedAccessKey, err
	}
	readerPubKey := publicClient.PublicClient.PublicKeys[e3dbClients.DefaultEncryptionKeyType]
	// Use the current clients private key for signing (to allow this client to sign the key)
	// and the readers public key for encryption (to allow the reader to decrypt)
	encryptionKeys := e3dbClients.EncryptionKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: readerPubKey,
		},
		Private: c.EncryptionKeys.Private,
	}
	eak, eakN, err := e3dbClients.BoxEncryptToBase64(accessKey[:], encryptionKeys)
	if err != nil {
		return wrappedAccessKey, err
	}
	wrappedAccessKey = fmt.Sprintf("%s.%s", eak, eakN)
	return wrappedAccessKey, nil

}

// GetOrCreateAccessKey gets and decrypts the access key for the given writer, user, client and record type,
// or creates a new one, returning the decrypted access key and error (if any).
func (c *E3dbPDSClient) GetOrCreateAccessKey(ctx context.Context, params GetOrCreateAccessKeyRequest) (e3dbClients.SymmetricKey, error) {
	var accessKey e3dbClients.SymmetricKey
	accessKeyResponse, err := c.GetAccessKey(ctx, GetAccessKeyRequest{
		WriterID:   params.WriterID,
		UserID:     params.UserID,
		ReaderID:   params.ReaderID,
		RecordType: params.RecordType,
	})
	// Check to see if the error was 404
	if err != nil {
		tozError, ok := err.(*e3dbClients.RequestError)
		if !ok {
			return accessKey, err
		}
		// If error was not 404 , return the error
		if tozError.StatusCode != http.StatusNotFound {
			return accessKey, err
		}
		// Otherwise continue as 404 is expected if no access key exists
	}
	// if no encrypted access key exists, create one
	if accessKeyResponse == nil {
		accessKey = e3dbClients.RandomSymmetricKey()
		// encrypt and store the created access key for later use
		eak, err := e3dbClients.EncryptAccessKey(accessKey, c.EncryptionKeys)
		if err != nil {
			return accessKey, err
		}
		_, err = c.PutAccessKey(ctx, PutAccessKeyRequest{
			WriterID:           params.WriterID,
			UserID:             params.UserID,
			ReaderID:           params.ReaderID,
			RecordType:         params.RecordType,
			EncryptedAccessKey: eak,
		})
		// return the un-encrypted version for local use
		return accessKey, err
	}
	encryptedAccessKey := accessKeyResponse.EAK
	// otherwise attempt to decrypt the returned access key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return accessKey, err
	}
	return e3dbClients.DecryptEAK(encryptedAccessKey, accessKeyResponse.AuthorizerPublicKey.Curve25519, rawEncryptionKey)
}

// New returns a new E3dbPDSClient configured with the specified apiKey and apiSecret values.
func New(config e3dbClients.ClientConfig) E3dbPDSClient {
	authService := authClient.New(config)
	return E3dbPDSClient{
		config.ClientID,
		config.APIKey,
		config.APISecret,
		config.Host,
		config.EncryptionKeys,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
