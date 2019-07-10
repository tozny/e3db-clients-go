package searchIndexerClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"os"
	"testing"
)

var (
	e3dbAuthHost          = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbSearchIndexerHost = os.Getenv("E3DB_SEARCH_INDEXER_HOST")
	e3dbAPIKey            = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret         = os.Getenv("E3DB_API_KEY_SECRET")
	ValidClientConfig     = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbSearchIndexerHost,
		AuthNHost: e3dbAuthHost,
	}
)

func TestIndexRecordSucceedsWithValidInput(t *testing.T) {
	indexer := New(ValidClientConfig)
	params := IndexRecordRequest{RecordId: "8344742e-2789-457b-bbc8-2ce070bca6ae"}
	ctx := context.Background()
	_, err := indexer.IndexRecord(ctx, params)
	if err != nil {
		t.Error(err)
	}
}

func TestBatchIndexRecordSucceedsWithValidInput(t *testing.T) {
	indexer := New(ValidClientConfig)
	params := BatchIndexRecordRequest{
		RecordIds: []string{
			"82db1d11-2145-488b-b271-2227def2e68d",
			"5ec5843e-3e64-44e0-8f45-27ff4ea9bbf7",
			"53860b16-c37c-4bdd-95b9-39a44b536ce7",
		},
	}
	ctx := context.Background()
	_, err := indexer.BatchIndexRecord(ctx, params)
	if err != nil {
		t.Error(err)
	}
}
