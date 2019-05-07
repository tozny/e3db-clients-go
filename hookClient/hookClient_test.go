package hookClient

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/pdsClient"
	helper "github.com/tozny/utils-go/test"
)

var (
	e3dbStorageHost      = os.Getenv("E3DB_STORAGE_SERVICE_HOST")
	e3dbAuthHost         = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost      = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	e3dbAPIKey           = os.Getenv("E3DB_API_KEY_ID")
	e3dbAPISecret        = os.Getenv("E3DB_API_KEY_SECRET")
	e3dbClientID         = os.Getenv("E3DB_CLIENT_ID")
	hookServiceHost      = os.Getenv("E3DB_HOOK_SERVICE_HOST")
	webhookURL           = os.Getenv("WEBHOOK_URL")
	ValidPDSClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbStorageHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbPDS                  = pdsClient.New(ValidPDSClientConfig)
	ValidAccountClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      e3dbAccountHost,
		AuthNHost: e3dbAuthHost,
	}
	e3dbAccountService       = accountClient.New(ValidAccountClientConfig)
	defaultPDSUserRecordType = "hook-client-integration-tests"
)

// TODO extract to github.com/tozny/utils-go/test
func MakeClientWriterForRecordType(pdsUser pdsClient.E3dbPDSClient, clientID string, recordType string) (string, error) {
	ctx := context.TODO()
	putEAKParams := pdsClient.PutAccessKeyRequest{
		WriterID:           clientID,
		UserID:             clientID,
		ReaderID:           clientID,
		RecordType:         recordType,
		EncryptedAccessKey: "SOMERANDOMNPOTENTIALLYNONVALIDKEY",
	}
	resp, err := pdsUser.PutAccessKey(ctx, putEAKParams)
	if err != nil {
		fmt.Printf("Error placing access key %s\n", err)
	}
	return resp.EncryptedAccessKey, err
}

func TestCreateWebHook(t *testing.T) {
	clientConfig, _, err := helper.MakeE3DBAccount(t, &e3dbAccountService, uuid.New().String(), e3dbAuthHost)
	if err != nil {
		t.Errorf("error %s unable to create authorizing client using %+v", err, e3dbAccountService)
	}
	client := New(clientConfig, hookServiceHost)
	createHookRequest := CreateHookRequest{
		WebhookURL: webhookURL,
		Triggers: []HookTrigger{
			HookTrigger{
				Enabled:  true,
				APIEvent: "authorizer_added",
			},
		},
	}
	ctx := context.TODO()
	response, err := client.CreateHook(ctx, createHookRequest)
	if err != nil {
		t.Errorf("Error %s calling CreateWebHook with %+v\n", err, createHookRequest)
	}
	if response.WebhookURL == "" {
		t.Errorf("Expected created webhook to have an id, got %+v\n", response)
	}
}