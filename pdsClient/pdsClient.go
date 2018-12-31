package pdsClient

import (
    "bytes"
    "context"
    "encoding/json"
    "github.com/tozny/e3db-clients-go"
    "github.com/tozny/e3db-clients-go/authClient"
    "net/http"
)

const (
    PDSServiceBasePath = "v1/storage" //HTTP PATH prefix for calls to the Personal Data Storage service
)

//E3DBAuthClient implements an http client for communication with an e3db PDS service.
type E3dbPDSClient struct {
    APIKey    string
    APISecret string
    Host      string
    *authClient.E3DBAuthClient
}

// ListRecords returns a list of records using any filters provided as params, and error (if any).
func (c *E3dbPDSClient) ListRecords(ctx context.Context, params ListRecordsRequest) (*ListRecordsResult, error) {
    var result *ListRecordsResult
    client := c.E3DBAuthClient.AuthHTTPClient(ctx)
    var buf bytes.Buffer
    err := json.NewEncoder(&buf).Encode(&params)
    if err != nil {
        return result, err
    }
    request, err := http.NewRequest("POST", c.Host+"/"+PDSServiceBasePath+"/search", &buf)
    if err != nil {
        return result, err
    }
    response, err := client.Do(request)
    if err != nil {
        return result, err
    }
    defer response.Body.Close()
    err = json.NewDecoder(response.Body).Decode(&result)
    if err != nil {
        return result, err
    }
    return result, err
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
