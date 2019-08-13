package notificationClient_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/notificationClient"
	"github.com/tozny/e3db-clients-go/test"
	"github.com/tozny/utils-go"
)

var (
	toznyCyclopsHost                 = utils.MustGetenv("TOZNY_CYCLOPS_SERVICE_HOST")
	e3dbAPIKey                       = utils.MustGetenv("E3DB_API_KEY_ID")
	e3dbAPISecret                    = utils.MustGetenv("E3DB_API_KEY_SECRET")
	bootstrapClientPublicSigningKey  = utils.MustGetenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	bootstrapClientPrivateSigningKey = utils.MustGetenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	ValidClientConfig                e3dbClients.ClientConfig
)

func TestMain(m *testing.M) {
	ValidClientConfig = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      toznyCyclopsHost,
		AuthNHost: toznyCyclopsHost,
		SigningKeys: e3dbClients.SigningKeys{
			Public: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: bootstrapClientPublicSigningKey,
			},
			Private: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: bootstrapClientPrivateSigningKey,
			},
		},
	}
	os.Exit(m.Run())
}

func TestSendNotification(t *testing.T) {
	testTag := uuid.New().String()

	accounter := accountClient.New(ValidClientConfig)
	notifier := notificationClient.New(ValidClientConfig)

	_, account, err := test.MakeE3DBAccount(t, &accounter, testTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Failed to create a test account: %s", err)
	}
	notificationMeta, err := notifier.CreateNotification(context.Background(), notificationClient.CreateNotificationRequest{
		Template:  "expiry_30days",
		Payload:   nil,
		Channel:   "email",
		AccountID: uuid.MustParse(account.Profile.AccountID),
		Nonce:     testTag,
		SendAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to send a notification: %s", err)
	}
	if notificationMeta.Nonce != testTag {
		t.Errorf("The nonce returned from notification-service did not match the nonce we sent. Expected %q, but got %q", testTag, notificationMeta.Nonce)
	}
}

func TestSendInvalidTemplate(t *testing.T) {
	testTag := uuid.New().String()
	accounter := accountClient.New(ValidClientConfig)
	notifier := notificationClient.New(ValidClientConfig)

	_, account, err := test.MakeE3DBAccount(t, &accounter, testTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Failed to create a test account: %s", err)
	}
	_, err = notifier.CreateNotification(context.Background(), notificationClient.CreateNotificationRequest{
		Template:  "not-a-real-template",
		Payload:   nil,
		Channel:   "email",
		AccountID: uuid.MustParse(account.Profile.AccountID),
		Nonce:     uuid.New().String(),
		SendAt:    time.Now(),
	})
	if err == nil {
		t.Fatalf("Somehow sent a notification with a nonexistent template")
	}
}
