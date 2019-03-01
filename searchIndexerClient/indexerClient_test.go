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
	params := IndexRecordRequest{RecordId: "8344742e-2789-457b-bbc8-2ce070bca6ae"}
	ctx := context.TODO()
	_, err := indexer.IndexRecord(ctx, params)
	if err != nil {
		t.Error(err)
	}
}

func TestBatchIndexRecordSucceedsWithValidInput(t *testing.T) {
	indexer := New(ValidClientConfig, e3dbSearchIndexerHost)
	params := BatchIndexRecordRequest{
		RecordIds: []string{
			"82db1d11-2145-488b-b271-2227def2e68d",
			"5ec5843e-3e64-44e0-8f45-27ff4ea9bbf7",
			"53860b16-c37c-4bdd-95b9-39a44b536ce7",
		},
	}
	ctx := context.TODO()
	_, err := indexer.BatchIndexRecord(ctx, params)
	if err != nil {
		t.Error(err)
	}
}
