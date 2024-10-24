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

// ClientGetPublicResponse is the client information from the endpoint /<client_id>/public
type ClientGetPublicResponse struct {
	PublicClient
}

// ClientBatchPublicInfoRequest is a list of clientIDs to get public information for.
type ClientBatchPublicInfoRequest struct {
	ClientIDs []string `json:"client_ids"`
}

// ClientBatchPublicInfoResponse is the a map of client ID to public client information from endpoint /public.
type ClientBatchPublicInfoResponse struct {
	Clients map[uuid.UUID]PublicClient `json:"clients"`
}

// ClientRegisterRequest captures the information sent to create a client.
type ClientRegisterRequest struct {
	RegistrationToken string             `json:"token"`
	Client            ClientRegisterInfo `json:"client"`
}

// ClientRegisterInfo is the client definition required to create a new client.
type ClientRegisterInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitemtpy"`
}

// BackfillClientSigningKeysRequest wraps the information needed to patch signing keys
type BackfillClientSigningKeysRequest struct {
	// Public Signing Key
	ClientID    uuid.UUID
	SigningKeys map[string]string `json:"signing_key"`
}

// ClientRegisterResponse sends back the client information for a newly registered client
type ClientRegisterResponse struct {
	Client
	APISecret string `json:"api_secret"`
}

type ClientInfoForSignatureRequest struct {
	ClientID  string `json:"client_id"`
	PublicKey string `json:"public_key"`
}

type ClientInfoForTokenClaimsRequest struct {
	ClientID string `json:"client_id"`
}

type InternalClientPatchBackupRequest struct {
	ClientID  string
	HasBackup bool `json:"has_backup"`
}

type InternalAccountIDForClientIDResponse struct {
	AccountID string `json:"account_id"`
}

type InternalToggleEnabledRequest struct {
	ClientID string
	Enabled  bool `json:"enabled"`
}

type AdminToggleClientEnabledRequest struct {
	ClientID string
	Enabled  bool `json:"enabled"`
}

// Client is all the information the user gets to see about their client.
type Client struct {
	ClientID    uuid.UUID         `json:"client_id"`
	APIKeyID    string            `json:"api_key_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	HasBackup   bool              `json:"has_backup"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitemtpy"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// PublicClient is the public information any client can see about a client.
type PublicClient struct {
	ClientID    uuid.UUID         `json:"client_id"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitemtpy"`
}

type IssueEmailChallengeRequest struct {
	AccountID string `json:"account_id"`
	Endpoint  string `json:"endpoint"`
	Lifespan  int    `json:"lifespan"`
	Context   string `json:"context"`
	Send      bool   `json:"send"`
	Data      string `json:"data"`
}

type IssueEmailChallengeResponse struct {
	Link string `json:"link"`
}

type VerifyEmailChallengeRequest struct {
	ID  string `json:"id"`
	OTP string `json:"otp"`
}

type InternalRollQueenClientRequest struct {
	AccountID         string             `json:"account_id"`
	RegistrationToken string             `json:"token"`
	Client            ClientRegisterInfo `json:"client"`
}

// A request body for the Client List endpoint
type InternalClientListRequest struct {
	NextToken int64 `json:"next_token"`
	Limit     int   `json:"limit"`
}

// A response body for the Client List endpoint
type InternalClientListResponse struct {
	ClientIDs []string `json:"client_ids"`
	NextToken int64    `json:"next_token"`
}

type ClientInfo struct {
	ClientID  string `json:"client_id"`
	IsDeleted bool   `json:"status"`
}
type InternalClientInfoListResponse struct {
	Clients   []ClientInfo `json:"client_ids"`
	NextToken int64        `json:"next_token"`
}

type InternalClientDeleteRequest struct {
	RealmName    string `json:"realm_name"`
	ClientID     string `json:"client_id"`
	DeleteShared string `json:"delete_shared"`
}
