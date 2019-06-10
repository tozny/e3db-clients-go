package clientServiceClient

import (
	"github.com/google/uuid"
)

// AdminListRequest is the information sent to the paginated /admin GET endpooint,
// to get the clients for a specific account (determined by authN).
type AdminListRequest struct {
	NextToken int64 `json:"next_token"`
	Limit     int   `json:"limit"`
}

// AdminListResponse is a list of client information associated with a specific accountID (authN) and page.
type AdminListResponse struct {
	Clients   []Client `json:"clients"`
	NextToken int64    `json:"next_token"`
}

// AdminGetResponse is the client information from the endpoint /admin/<client_id>,
// owned by the account that authenticated this call.
type AdminGetResponse struct {
	Client
}

// ClientGetResponse is the client information from the endpoint /<client_id>
type ClientGetResponse struct {
	Client
}

// ClientRegisterRequest captures the information sent to create a client.
type ClientRegisterRequest struct {
	RegistrationToken string `json:"token"`
	Client            struct {
		Name       string            `json:"name"`
		Type       string            `json:"type"`
		PublicKey  map[string]string `json:"public_key"`
		SigningKey map[string]string `json:"signing_key,omitemtpy"`
	} `json:"client"`
}

// ClientRegisterResponse sends back the client information for a newly registered client
type ClientRegisterResponse struct {
	Client
	APISecret string `json:"api_secret"`
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
