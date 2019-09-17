package storageClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
)

const (
	storageServiceBasePath = "/v2/storage"
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

func (c *StorageClient) ReadNote(ctx context.Context, noteID string) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("note_id", noteID)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) Challenge(ctx context.Context, noteID string) ([]string, error) {
	path := c.Host + storageServiceBasePath + "/notes/challenge"
	request, err := e3dbClients.CreateRequest("PATCH", path, nil)
	var challenges []string
	if err != nil {
		return challenges, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("note_id", noteID)
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, challenges)
	return challenges, err
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
