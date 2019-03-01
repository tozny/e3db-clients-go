package searchIndexerClient

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
	"net/http"
)

const (
	SearchIndexerServiceBasePath = "v2/index" //HTTP PATH prefix for calls to the Search Indexer service
)

//E3dbSearchIndexerClient implements an http client for communication with an e3db Search Indexer service.
type E3dbSearchIndexerClient struct {
	APIKey    string
	APISecret string
	Host      string
	*authClient.E3dbAuthClient
}

// IndexRecord attempts to index the provided record by calling the indexer index endpoint.
func (c *E3dbSearchIndexerClient) IndexRecord(ctx context.Context, params IndexRecordRequest) (*IndexRecordResponse, error) {
	var result *IndexRecordResponse
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return result, err
	}
	request, err := http.NewRequest("POST", c.Host+"/"+SearchIndexerServiceBasePath, &buf)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
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
	request, err := http.NewRequest("POST", c.Host+"/"+SearchIndexerServiceBasePath+"/batch", &buf)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(c.E3dbAuthClient, ctx, request, &result)
	return result, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(authConfig e3dbClients.ClientConfig, indexerHost string) E3dbSearchIndexerClient {
	authService := authClient.New(authConfig)
	return E3dbSearchIndexerClient{
		authConfig.APIKey,
		authConfig.APISecret,
		indexerHost,
		&authService,
	}
}
