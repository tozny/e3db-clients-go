package clientServiceClient

import (
	"github.com/google/uuid"
)

type AdminListRequest struct {
	NextToken int64 `json:"next_token"`
	Limit     int   `json:"limit"`
}

type AdminListResponse struct {
	Clients   []Client `json:"clients"`
	NextToken int64    `json:"next_token"`
}

// Client is all the information the user gets to see about their client.
type Client struct {
	ClientID    uuid.UUID         `json:"client_id"`
	APIKeyID    string            `json:"api_key_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitemtpy"`
	Meta        map[string]string `json:"meta,omitempty"`
}
