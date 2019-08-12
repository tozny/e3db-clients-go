package notificationClient_test

import (
	"context"
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
	e3dbAuthHost          = utils.MustGetenv("E3DB_AUTH_SERVICE_HOST")
	e3dbAccountHost       = utils.MustGetenv("E3DB_ACCOUNT_SERVICE_HOST")
	toznyNotificationHost = utils.MustGetenv("TOZNY_NOTIFICATION_SERVICE_HOST")
	e3dbAPIKey            = utils.MustGetenv("E3DB_API_KEY_ID")
	e3dbAPISecret         = utils.MustGetenv("E3DB_API_KEY_SECRET")
	ValidClientConfig     = e3dbClients.ClientConfig{
		APIKey:    e3dbAPIKey,
		APISecret: e3dbAPISecret,
		Host:      toznyNotificationHost,
		AuthNHost: e3dbAuthHost,
	}
)

func TestSendNotification(t *testing.T) {
	testTag := uuid.New().String()
	accounter := accountClient.New(e3dbClients.ClientConfig{
		APIKey:    ValidClientConfig.APIKey,
		APISecret: ValidClientConfig.APISecret,
		AuthNHost: ValidClientConfig.AuthNHost,
		Host:      e3dbAccountHost,
	})
	notifier := notificationClient.New(ValidClientConfig)

	_, account, err := test.MakeE3DBAccount(t, &accounter, testTag, e3dbAuthHost)
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
	accounter := accountClient.New(e3dbClients.ClientConfig{
		APIKey:    ValidClientConfig.APIKey,
		APISecret: ValidClientConfig.APISecret,
		AuthNHost: ValidClientConfig.AuthNHost,
		Host:      e3dbAccountHost,
	})
	notifier := notificationClient.New(ValidClientConfig)

	_, account, err := test.MakeE3DBAccount(t, &accounter, testTag, e3dbAuthHost)
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
