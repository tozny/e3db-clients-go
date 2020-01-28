package notificationClient

import (
	"time"

	"github.com/google/uuid"
)

const (
	ChannelEmail = "email"
)

// UserContactInfo is specfic information about the entity to be contacted
type UserContactInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// CreateNotificationRequest is the api-level struct which represents an object expected by notification-service's POST / endpoint
type CreateNotificationRequest struct {
	Template  string            `json:"template"`
	Payload   map[string]string `json:"template_payload,omitempty"`
	Channel   string            `json:"channel"`
	AccountID uuid.UUID         `json:"account_id"`
	Nonce     string            `json:"nonce"`
	// SendAt optionally specifies a suggested time when the notification should be sent
	SendAt time.Time       `json:"send_at,omitempty"`
	Target UserContactInfo `json:"target,omitempty"`
}

// NotificationMeta is the metadata about a notification which, eg, returned when creating a notification
type NotificationMeta struct {
	NotificationID uuid.UUID `json:"notification_id"`
	Nonce          string    `json:"nonce"`
}

// DirectMobilePushRequestWithPayload sends a push request directly to a single user with a data payload.
type DirectMobilePushRequestWithPayload struct {
	Title           string            `json:"title"`
	Body            string            `json:"body"`
	OneSignalUserID string            `json:"one_signal_user_id"`
	Data            map[string]string `json:"data"`
	Buttons         []PushButton      `json:"buttons"`
}

type PushButton struct {
	ActionID  string `json:"action_id"`
	Text      string `json:"text"`
	LaunchURL string `json:"launch_url"`
}

type PushResponse struct {
	PushID string `json:"id"`
}
