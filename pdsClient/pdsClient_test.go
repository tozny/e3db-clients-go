package pdsClient

import (
    "context"
    "github.com/tozny/e3db-clients-go"
    "os"
    "testing"
)

var e3dbBaseURL = os.Getenv("E3DB_API_URL")
var e3dbAPIKey = os.Getenv("E3DB_API_KEY_ID")
var e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")

func TestListRecordsSucceedsWithValidClientCredentials(t *testing.T) {
    config := e3dbClients.ClientConfig{
        APIKey:    e3dbAPIKey,
        APISecret: e3dbAPISecret,
        Host:      e3dbBaseURL,
    }
    e3dbPDS := New(config)
    ctx := context.TODO()
    params := ListRecordsRequest{
        Count:             50,
        IncludeAllWriters: true,
    }
    _, err := e3dbPDS.ListRecords(ctx, params)
    if err != nil {
        t.Error(err)
    }
}
