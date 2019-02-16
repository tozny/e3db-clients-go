package accountClient

import (
	"context"
	"github.com/tozny/e3db-clients-go"
	"os"
	"testing"
	"strings"
)

var e3dbBaseURL = os.Getenv("E3DB_API_URL")
var e3dbAPIKey = os.Getenv("E3DB_API_KEY_ID")
var e3dbAPISecret = os.Getenv("E3DB_API_KEY_SECRET")
var e3dbClientID = os.Getenv("E3DB_CLIENT_ID")
var ValidClientConfig = e3dbClients.ClientConfig{
	APIKey:    e3dbAPIKey,
	APISecret: e3dbAPISecret,
	Host:      e3dbBaseURL,
}

func TestInternalGetClientAccountReturns404ForClientsWithNoAccount(t *testing.T) {
	// Create internal account client
	accounter := New(ValidClientConfig)
	// Make request
	ctx := context.TODO()
	account, err := accounter.InternalGetClientAccount(ctx, e3dbClientID)
	if err != nil {
		t.Errorf("Error %s trying to get account info for client %+v\n", err, accounter)
	}
	// Verify account id for this client is returned
	if err != nil {
		t.Errorf("Expected non 200 status code/error fetching account id for non-existent client, got %s for %+v\n", err, account)
	}
	if !strings.Contains(err.Error(), "http error 404") {
		t.Errorf("Expected 404 response, got %s",err)
	}
}
