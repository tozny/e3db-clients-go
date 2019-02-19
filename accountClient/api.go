package accountClient

import ()

// ClientKey contains a cryptographic key for use in client level resource encryption operations(e.g. encrypting and decrypting record data).
type EncryptionKey struct {
	Ed25519 string `json:"ed25519"`
}

// ClientKey contains a cryptographic key for use in client operations.
type ClientKey struct {
	Curve25519 string `json:"curve25519,omitempty"`
	P384       string `json:"p384,omitempty"` // NIST/FIPS approved curve
}

// Account represents an e3db account.
type Account struct {
	Company   string    `json:"company"`
	Plan      string    `json:"plan"`
	PublicKey ClientKey `json:"public_key"`
	Client    *Client   `json:"client,omitempty"`
}

// Client represents an e3db client.
type Client struct {
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	PublicKey    ClientKey `json:"public_key"`
	APIKeyID     string    `json:"api_key_id"`
	APISecretKey string    `json:"api_secret"`
	SigningKey   string    `json:"signing_key"`
	Enabled      bool      `json:"enabled"`
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

// CreateAccountRequest wraps parameters needed to make a valid
// create account request to the e3db account service.
type CreateAccountRequest struct {
	Profile Profile `json:"profile"`
	Account Account `json:"account"`
}

// CreateAccountRequest represents a response from making a
// create account request to the e3db account service.
type CreateAccountResponse struct {
	RegistrationToken string  `json:"token"`
	Profile           Profile `json:"profile"`
	Account           Account `json:"account"`
}

// InternalGetClientAccountResponse represents a response
// from calling the Account /client endpoint
type InternalGetClientAccountResponse struct {
	AccountID string `json:"account_id"`
}
