package notificationClient

import (
	"context"
	"net/http"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/authClient"
)

type ToznyNotificationClient struct {
	Host        string
	SigningKeys e3dbClients.SigningKeys
	ClientID    string
	authClient  authClient.E3dbAuthClient
}

const (
	// NotificationServiceBasePath is the base path used for notification-service calls
	NotificationServiceBasePath = "/v1/notification"
)

// CreateNotification pushes a notification, requires the bootstrap client.
func (nc *ToznyNotificationClient) CreateNotification(ctx context.Context, params CreateNotificationRequest) (*NotificationMeta, error) {
	var result *NotificationMeta
	path := nc.Host + NotificationServiceBasePath + "/"
	request, err := e3dbClients.CreateRequest(http.MethodPost, path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, nc.SigningKeys, nc.ClientID, &result)
	return result, err
}

// DirectMobilePush sends a mobile push notification to a single user, requires the bootstrap client.
func (nc *ToznyNotificationClient) DirectMobilePush(ctx context.Context, params DirectMobilePushRequestWithPayload) (*PushResponse, error) {
	var result *PushResponse
	path := nc.Host + NotificationServiceBasePath + "/direct-mobile-push"
	request, err := e3dbClients.CreateRequest(http.MethodPost, path, params)
	if err != nil {
		return result, e3dbClients.NewError(err.Error(), path, 0)
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, nc.SigningKeys, nc.ClientID, &result)
	return result, err
}

func New(config e3dbClients.ClientConfig) *ToznyNotificationClient {
	return &ToznyNotificationClient{
		SigningKeys: config.SigningKeys,
		ClientID:    config.ClientID,
		Host:        config.Host,
		authClient:  authClient.New(config),
	}
}
