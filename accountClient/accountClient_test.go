package accountClient_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	e3dbAuthHost      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey        = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret     = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID      = os.Getenv("E3DB_CLIENT_ID")
	ValidClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
)

func TestInternalGetClientAccountReturnsClientsAccountId(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidClientConfig)
	ctx := context.TODO()
	accountTag := uuid.New().String()
	_, response, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
	if err != nil {
		t.Fatalf("Failure Creating New Account\n")
	}
	accountID := response.Profile.AccountID
	clientID := response.Account.Client.ClientID
	// Make request to lookup the account for this account's client
	account, err := accounter.InternalGetClientAccount(ctx, clientID)
	if err != nil {
		t.Errorf("Error %s trying to get account info for client %+v\n", err, accounter)
	}
	// Verify correct account id for this client is returned
	if account.AccountID != accountID {
		t.Errorf("Expected account id to be %s, got %s", accountID, account.AccountID)
	}
}
