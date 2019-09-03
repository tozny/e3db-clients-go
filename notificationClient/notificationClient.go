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

// CreateNotification pushes a notification via an internal endpoint. Requires the bootstrap client.
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

func New(config e3dbClients.ClientConfig) *ToznyNotificationClient {
	return &ToznyNotificationClient{
		SigningKeys: config.SigningKeys,
		ClientID:    config.ClientID,
		Host:        config.Host,
		authClient:  authClient.New(config),
	}
}