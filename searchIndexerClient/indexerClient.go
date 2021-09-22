package searchIndexerClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/request"
)

const (
	InternalSearchServicesBasePath = "v2"
)

var (
	SearchIndexerServiceBasePath = fmt.Sprintf("%s/index", InternalSearchServicesBasePath) //HTTP PATH prefix for calls to the Search Indexer service
)

//E3dbSearchIndexerClient implements an http client for communication with an e3db Search Indexer service.
type E3dbSearchIndexerClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
	requester request.Requester
}

// InternalServiceCheck calls the internal service check endpoint for the indexer and returns error (if any)
func (c *E3dbSearchIndexerClient) InternalServiceCheck(ctx context.Context) error {
	path := c.Host + "/" + InternalSearchServicesBasePath + "/servicecheck"
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, nil)
}

// IndexRecord attempts to index the provided record by calling the indexer index endpoint.
func (c *E3dbSearchIndexerClient) IndexRecord(ctx context.Context, params IndexRecordRequest) (*IndexRecordResponse, error) {
	var result *IndexRecordResponse
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequest("POST", c.Host+"/"+SearchIndexerServiceBasePath, &buf)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// BatchIndexRecord attempts to index the provided records by calling the indexer index batch endpoint.
func (c *E3dbSearchIndexerClient) BatchIndexRecord(ctx context.Context, params BatchIndexRecordRequest) (*BatchIndexRecordResponse, error) {
	var result *BatchIndexRecordResponse
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequest("POST", c.Host+"/"+SearchIndexerServiceBasePath+"/batch", &buf)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) E3dbSearchIndexerClient {
	authService := authClient.New(config)
	return E3dbSearchIndexerClient{
		config.APIKey,
		config.APISecret,
		config.Host,
		&authService,
		request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}
