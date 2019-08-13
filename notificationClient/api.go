package notificationClient

import (
	"time"

	"github.com/google/uuid"
)

const (
	ChannelEmail = "email"
)

// CreateNotificationRequest is the api-level struct which represents an objcet expected by notification-service's POST / endpoint
type CreateNotificationRequest struct {
	Template  string            `json:"template"`
	Payload   map[string]string `json:"template_payload,omitempty"`
	Channel   string            `json:"channel"`
	AccountID uuid.UUID         `json:"account_id"`
	Nonce     string            `json:"nonce"`
	// SendAt optionally specifies a suggested time when the notification should be sent
	SendAt time.Time `json:"send_at,omitempty"`
}

// NotificationMeta is the metadata about a notification which, eg, returned when creating a notification
type NotificationMeta struct {
	NotificationID uuid.UUID `json:"notification_id"`
	Nonce          string    `json:"nonce"`
}
