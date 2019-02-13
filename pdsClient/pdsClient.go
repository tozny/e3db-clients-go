package pdsClient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"net/http"
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
// for read access to records
type readPolicy struct {
	Read map[string]interface{} `json:"read"`
}

// allowReadPolicy wraps an e3db API object granting read access to records
type allowReadPolicy struct {
	Allow []readPolicy `json:"allow"`
}

// / Share attempts to grants another e3db client permission to read records of the
// specified record type, returning error (if any).
func (c *E3dbPDSClient) ShareRecords(ctx context.Context, params ShareRecordsRequest) error {
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
		return errors.New("no applicable records exist to share")
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
	request, err := createRequest("PUT", path, sharePolicy)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, nil)
	return err
}

// InternalAllowedReads attempts to retrieve the list of AllowedRead policies for other users records for the given reader using an internal only e3db endpoint, returning InternalAllowedReadsResponse(which may or may not be empty of AllowedRead policies) and error (if any).
func (c *E3dbPDSClient) InternalAllowedReads(ctx context.Context, readerID string) (*InternalAllowedReadsResponse, error) {
	var result *InternalAllowedReadsResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/allowed_reads/" + readerID
	request, err := createRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// InternalRegisterClient uses an internal(available only to locally running e3db instances) endpoint to register a client, returning the registered client and error (if any).
func (c *E3dbPDSClient) InternalRegisterClient(ctx context.Context, params RegisterClientRequest) (*RegisterClientResponse, error) {
	var result *RegisterClientResponse
	path := c.Host + "/" + PDSServiceBasePath + "/clients"
	request, err := createRequest("POST", path, params)
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// PutAccessKey attempts to set an access key that E3DB will enforce be used to write records of the specified type for the specified user, client, and writer, returning the response and error (if any).
func (c *E3dbPDSClient) PutAccessKey(ctx context.Context, params PutAccessKeyRequest) (*PutAccessKeyResponse, error) {
	var result *PutAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	request, err := createRequest("PUT", path, params)
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// GetAccessKey attempts to get an access key stored in E3DB returning the response and error (if any).
func (c *E3dbPDSClient) GetAccessKey(ctx context.Context, params GetAccessKeyRequest) (*GetAccessKeyResponse, error) {
	var result *GetAccessKeyResponse
	path := c.Host + "/" + PDSServiceBasePath + "/access_keys" + fmt.Sprintf("/%s", params.WriterID) + fmt.Sprintf("/%s", params.UserID) + fmt.Sprintf("/%s", params.ReaderID) + fmt.Sprintf("/%s", params.RecordType)
	request, err := createRequest("GET", path, params)
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// WriteRecord attempts to store a record in e3db, returning stored record and error (if any).
// XXX: Data is not encrypted in this method, it is the caller's responsibility to ensure data is encrypted before sending to e3db.
func (c *E3dbPDSClient) WriteRecord(ctx context.Context, params WriteRecordRequest) (*WriteRecordResponse, error) {
	var result *WriteRecordResponse
	path := c.Host + "/" + PDSServiceBasePath + "/records"
	request, err := createRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// ListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ListRecords(ctx context.Context, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	request, err := createRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// ProxyListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ProxyListRecords(ctx context.Context, authToken string, params ListRecordsRequest) (*ListRecordsResult, error) {
	var result *ListRecordsResult
	path := c.Host + "/" + PDSServiceBasePath + "/search"
	request, err := createRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeProxiedUserCall(ctx, authToken, request, &result)
	return result, err
}

// InternalGetRecord attempts to get a record using an internal only e3db endpoint, returning fetched record and error (if any).
func (c *E3dbPDSClient) InternalGetRecord(ctx context.Context, recordID string) (*InternalGetRecordResponse, error) {
	var result *InternalGetRecordResponse
	path := c.Host + "/internal/" + PDSServiceBasePath + "/records/" + recordID
	request, err := createRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// createRequest isolates duplicate code in creating http search request.
func createRequest(method string, path string, params interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	var request *http.Request
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return request, err
	}
	request, err = http.NewRequest(method, path, &buf)
	return request, err
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
