package searchIndexerClient

import (
    "context"
    "github.com/tozny/e3db-clients-go"
    "os"
    "testing"
)

var e3dbBaseURL = os.Getenv("E3DB_API_URL")
var e3dbAPIKey = os.Getenv("E3DB_API_KEY_ID")
var e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")
var e3dbSearchIndexerHost = os.Getenv("E3DB_SEARCH_INDEXER_HOST")
var ValidClientConfig = e3dbClients.ClientConfig{
    APIKey:    e3dbAPIKey,
    APISecret: e3dbAPISecret,
    Host:      e3dbBaseURL,
}

func TestIndexRecordSucceedsWithValidInput(t *testing.T) {
    indexer := New(ValidClientConfig, e3dbSearchIndexerHost)
    params := IndexRecordRequest{RecordId: "some-id"}
    ctx := context.TODO()
    response, err := indexer.IndexRecord(ctx, params)
    if err != nil {
        t.Error(err)
    }
    t.Log(response)
}
