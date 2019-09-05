package metricClient

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
	e3dbAuthHost              = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost           = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbCyclopsHost           = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	e3dbClientHost            = os.Getenv("E3DB_CLIENT_SERVICE_HOST")
	e3dbAPIKey                = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret             = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID              = os.Getenv("E3DB_CLIENT_ID")
	ValidInternalClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
)

func TestQueenAuth(t *testing.T) {
	// Create internal account client
	accounter := accountClient.New(ValidInternalClientConfig)
	ctx := context.Background()
	accountTag := uuid.New().String()
	config, response, err := test.MakeE3DBAccount(t, &accounter, accountTag, e3dbAuthHost)
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
	config.Host = e3dbCyclopsHost
	queenMetricsClient := New(config)
	req := APIMetricsRequest{
		Limit:       10,
		ExcludeLogs: true,
		AccountID:   response.Profile.AccountID,
	}
	_, err = queenMetricsClient.RequestsMetrics(ctx, req)
	if err != nil {
		t.Fatalf("Error retrieving metrics with queen client. Error: %v\n", err)
	}
	token, err := accounter.CreateRegistrationToken(ctx, accountClient.CreateRegistrationTokenRequest{
		AccountServiceToken: response.AccountServiceToken,
		TokenPermissions: accountClient.TokenPermissions{
			Enabled: true,
			OneTime: false,
		},
		Name: "Plebes only",
	})
	if err != nil {
		t.Fatalf("Failure to get a registration token")
	}
	clientName := uuid.New().String()
	_, regularClientConfig, err := test.RegisterClient(ctx, e3dbClientHost, token.Token, clientName)
	if err != nil {
		t.Fatalf("Failed to register non-queen client. Err: %v\n", err)
	}
	regularClientConfig.Host = e3dbCyclopsHost
	regularMetricsClient := New(regularClientConfig)
	_, err = regularMetricsClient.RequestsMetrics(ctx, req)
	if err == nil {
		t.Fatalf("Non-queen clients should not be allowed to make requests to metrics, via cyclops.\n")
	}
}
