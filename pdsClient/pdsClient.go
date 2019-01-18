package pdsClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"net/http"
)

const (
	PDSServiceBasePath = "v1/storage" //HTTP PATH prefix for calls to the Personal Data Storage service
)

//E3dbAuthClient implements an http client for communication with an e3db PDS service.
type E3dbPDSClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
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

// createListRecordsRequest isolates duplicate code in creating http search request.
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
