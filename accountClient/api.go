package accountClient

import (
	"github.com/google/uuid"
)

// EncryptionKey contains a cryptographic key for use in client level resource encryption operations(e.g. encrypting and decrypting record data).
type EncryptionKey struct {
	Ed25519 string `json:"ed25519"`
}

// ClientKey contains a cryptographic key for use in client operations such as signing and encryption.
type ClientKey struct {
	Curve25519 string `json:"curve25519,omitempty"`
	P384       string `json:"p384,omitempty"` // NIST/FIPS approved curve
}

// Profile wraps profile configuration for an e3db account.
type Profile struct {
	AccountID               string        `json:"id,omitempty"`
	Name                    string        `json:"name"`
	Email                   string        `json:"email"`
	AuthenticationSalt      string        `json:"auth_salt"`
	EncodingSalt            string        `json:"enc_salt"`
	SigningKey              EncryptionKey `json:"signing_key"`
	PaperAuthenticationSalt string        `json:"paper_auth_salt"`
	PaperEncodingSalt       string        `json:"paper_enc_salt"`
	PaperSigningKey         EncryptionKey `json:"paper_signing_key"`
	Verified                bool          `json:"verified,omitempty"`
}

// Account represents an e3db account.
type Account struct {
	Company    string        `json:"company"`
	Plan       string        `json:"plan"`
	PublicKey  ClientKey     `json:"public_key"`
	SigningKey EncryptionKey `json:"signing_key,omitempty"`
	Client     *Client       `json:"client,omitempty"`
}

// Client represents an e3db client.
type Client struct {
	ClientID     string        `json:"client_id"`
	Name         string        `json:"name"`
	PublicKey    ClientKey     `json:"public_key"`
	APIKeyID     string        `json:"api_key_id"`
	APISecretKey string        `json:"api_secret"`
	SigningKey   EncryptionKey `json:"signing_key"`
	Enabled      bool          `json:"enabled"`
}

// CreateAccountRequest wraps parameters needed to make a valid
// create account request to the e3db account service.
type CreateAccountRequest struct {
	Profile Profile `json:"profile"`
	Account Account `json:"account"`
}

// CreateAccountResponse represents a response from making a
// create account request to the e3db account service.
type CreateAccountResponse struct {
	AccountServiceToken string  `json:"token"` // JWT token for subsequent requests to the account service.
	Profile             Profile `json:"profile"`
	Account             Account `json:"account"`
}

type ClientRegistrationRequest struct {
	Token  string                 `json:"token"`
	Client ClientRegistrationInfo `json:"client"`
}

// ClientRegistrationResponse contains information about a newly-registered E3DB client
type ClientRegistrationResponse struct {
	ClientID     string    `json:"client_id"`
	APIKeyID     string    `json:"api_key_id"`
	APISecret    string    `json:"api_secret"`
	PublicKey    ClientKey `json:"public_key"`
	Name         string    `json:"name"`
	RootClientID string
}

type ClientRegistrationInfo struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	PublicKey  ClientKey     `json:"public_key"`
	SigningKey EncryptionKey `json:"signing_key,omitempty"`
}

// ProxiedClientRegistrationRequest wraps information for creating a new client.
type ProxiedClientRegistrationRequest struct {
	RegistrationToken string                         `json:"token"`
	Client            ProxiedClientRegisterationInfo `json:"client"`
}

// ProxiedClientRegisterationInfo is the client definition required to create a new client.
type ProxiedClientRegisterationInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitempty"`
}

// ProxiedClientRegistrationResponse wraps the client information for a newly registered client.
type ProxiedClientRegistrationResponse struct {
	ProxyiedRegisteredClient
	APISecret    string `json:"api_secret"`
	RootClientID string
}

// ProxyiedRegisteredClient is all the information the user gets to see about their client.
type ProxyiedRegisteredClient struct {
	ClientID    uuid.UUID         `json:"client_id"`
	APIKeyID    string            `json:"api_key_id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	HasBackup   bool              `json:"has_backup"`
	PublicKeys  map[string]string `json:"public_key"`
	SigningKeys map[string]string `json:"signing_key,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// InternalGetClientAccountResponse represents a response
// from calling the Account /client endpoint
type InternalGetClientAccountResponse struct {
	AccountID string `json:"account_id"`
}

// ValidateTokenRequest represents a valid request to the account service's auth/validate endpoint.
type ValidateTokenRequest struct {
	Token string `json:"token"` //The token to validate
}

// ValidateTokenResponse represents the result of calling the account service's auth/validate endpoint.
type ValidateTokenResponse struct {
	AccountID string `json:"account_id"` //The account ID associated with this token
	Valid     bool   `json:"valid"`      //Whether the token was valid
}

// CreateRegistrationTokenRequest represents a valid request to the account service's /tokens endpoint POST.
type CreateRegistrationTokenRequest struct {
	AccountServiceToken string `json:"token"` // JWT token for subsequent requests to the account service.
	TokenPermissions    `json:"permissions"`
	Name                string `json:"name"`
	TotalAllowedUses    int    `json:"total_uses_allowed"`
	Uses                int    `json:"uses"`
}

// CreateRegTokenResponse represents the result of calling the account service's /tokens POST endpoint.
type CreateRegTokenResponse = ClientRegistrationToken

// ClientRegistrationToken wraps values related to a client registration token
type ClientRegistrationToken struct {
	Token            string           `json:"token"`
	Name             string           `json:"name,omitempty"` // Optional name used for identifying tokens
	Permissions      TokenPermissions `json:"permissions"`
	Uses             int              `json:"uses"` // The number of times the token has been used
	TotalAllowedUses int              `json:"total_uses_allowed"`
}

// ListRegistrationTokensResponse wraps the response from listing an accounts registration tokens
type ListRegistrationTokensResponse = []ClientRegistrationToken

// DeleteRegistrationTokenRequest wraps values needed to issue a delete registration request
type DeleteRegistrationTokenRequest struct {
	Token               string
	AccountServiceToken string
}

// TokenPermissions permissions associated with a registration token.
// called ClientPermissions in the account service spec
type TokenPermissions struct {
	Enabled      bool     `json:"enabled"`       // Flag a newly created client as enabled even if the default behavior is creating disabled clients
	OneTime      bool     `json:"one_time"`      // Automatically delete the token after it's been used to register a client
	AllowedTypes []string `json:"allowed_types"` // What client types can be registered using this token
}

// RegTokenInfo is the return from the token endpoint on a valid request
type RegTokenInfo struct {
	Token            string
	AccountID        uuid.UUID           `json:"account_id"`
	Permissions      RegTokenPermissions `json:"permissions"`
	Name             string              `json:"name"`
	TotalAllowedUses int                 `json:"total_uses_allowed"`
	Uses             int                 `json:"uses"`
}

// RegTokenPermissions decodes needed token permissions
type RegTokenPermissions struct {
	Enabled      bool
	AllowedTypes []string `json:"allowed_types"`
}

// InternalGetAccountInfoResponse represents a response from calling the account service
// internal/v1/account/account-info/{account-id} endpoint
type InternalGetAccountInfoResponse struct {
	StripeID       string `json:"stripe_id"`
	SubscriptionID string `json:"stripe_subscription_id"`
}

// InternalAccountInfoResponse represents a response from calling the account service at
// internal/v1/account/info/{accountID}
type InternalAccountInfoResponse struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	AccountID string `json:"account_id"`
}

// InternalSigClientInfoResponse wraps the data returned from the
// /internal/v1/account/validate-signature-client endpoint
type InternalSigClientInfoResponse struct {
	Name       string    `json:"name"`
	ClientID   uuid.UUID `json:"client_id"`
	AccountID  uuid.UUID `json:"account_id"`
	PublicKey  string    `json:"public_key"`
	SigningKey string    `json:"signing_key"`
}

// DeleteAccountRequestData wraps the values needed for account deletion
type DeleteAccountRequestData struct {
	AccountID uuid.UUID
}
