package identityClient

import (
	"github.com/google/uuid"
)

// Realm represents the top level identity management resource for grouping and managing
// authentication and authorization of consuming application, identities, and sovereigns within a realm.
type Realm struct {
	ID                    int64     `json:"id"`                                 // Service defined unique identifier for the realm.
	Name                  string    `json:"name"`                               // User defined realm identifier.
	AdminURL              string    `json:"admin_url"`                          // URL for realm administration console.
	Active                bool      `json:"active"`                             // Whether the realm is active for applications and identities to consume.
	Sovereign             Sovereign `json:"sovereign"`                          // The realm's sovereign.
	BrokerIdentityToznyID uuid.UUID `json:"broker_identity_tozny_id,omitempty"` // The Tozny Client ID associated with the Identity used to broker interactions between the realm and it's Identities. Will be empty if no realm broker Identity has been registered.
}

// Sovereign represents the top level user of a realm
// (i.e. a user who is able to log into the realm,
// create/update/delete/view the realm properties and it's identities.)
type Sovereign struct {
	ID       int64  `json:"id"`       // Service defined unique identifier for the sovereign.
	Name     string `json:"name"`     // User defined sovereign identifier.
	Password string `json:"password"` // The sovereign's realm administration console login password.
}

// CreateRealmRequest wraps parameters needed to request creation of a realm.
type CreateRealmRequest struct {
	RealmName     string `json:"realm_name"`     // User defined realm identifier.
	SovereignName string `json:"sovereign_name"` // User defined identifier for the realm's sovereign.
}

// ListRealmsResponse wraps values returned from a list realms request.
type ListRealmsResponse struct {
	Realms []Realm `json:"realms"`
}

// Identity wraps a user of a given realm along with its authentication information.
type Identity struct {
	ID           int64             `json:"id"`
	ToznyID      uuid.UUID         `json:"tozny_id"` // Tozny Client ID
	RealmID      int64             `json:"realm_id"`
	RealmName    string            `json:"realm_name"`
	Name         string            `json:"name"`
	FirstName    string            `json:"first_name"`
	LastName     string            `json:"last_name"`
	APIKeyID     string            `json:"api_key_id"`
	APIKeySecret string            `json:"api_secret_key"`
	PublicKeys   map[string]string `json:"public_key"`
	SigningKeys  map[string]string `json:"signing_key"`
}

// RegisterIdentityRequest wraps parameters needed to create and register an identity with a realm.
type RegisterIdentityRequest struct {
	RealmRegistrationToken string   `json:"realm_registration_token"`
	RealmName              string   `json:"realm_name"`
	Identity               Identity `json:"identity"`
}

// RegisterIdentityResponse wraps values returned from a register identity request.
type RegisterIdentityResponse struct {
	Identity                   Identity  `json:"identity"`
	RealmBrokerIdentityToznyID uuid.UUID `json:"realm_broker_identity_tozny_id,omitempty"`
}

// IdentityLoginResponse wraps an extended OpenID v1.0 compatible Token Response
// that can be used to authenticate an identity as a member of a realm.
type IdentityLoginResponse struct {
	AccessToken           string `json:"access_token"`
	AccessTokenExpiresIn  int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_expires_in"`
	TokenType             string `json:"token_type"`
	IDToken               string `json:"id_token"`
	NotBeforePolicy       int    `json:"not-before-policy"`
	RawScopes             string `json:"scope"`
}

// InternalIdentityLoginRequest wraps the parameters needed to determine
// whether an authenticated Identity can log into the a realm.
type InternalIdentityLoginRequest struct {
	XToznyAuthNHeader string // The X-TOZNY-AUTHN-HEADER for the authenticated Identity.
	RealmName         string // The realm the authenticated Identity is trying to log in to.
}

// InternalIdentityLoginResponse wraps an internal
// authentication context for realm identities.
type InternalIdentityLoginResponse struct {
	Active    bool   `json:"active"`     // Whether the Identity is currently enabled for realm operations.
	RealmName string `json:"realm_name"` // The name of the realm the Identity is a member of.
	RealmID   int64  `json:"realm_id"`   // The ID of the realm the Identity is a member of.
	UserID    string `json:"user_id"`    // The ID of the Identity's Keycloak user.
}

// RegisterRealmBrokerIdentityRequest wraps parameters needed to create and register
// an Identity to use for brokering interactions between the realm and its Identities.
type RegisterRealmBrokerIdentityRequest struct {
	RealmRegistrationToken string `json:"realm_registration_token"`
	RealmName              string
	Identity               Identity `json:"identity"`
}

// RegisterRealmBrokerIdentityResponse wraps values returned from a RegisterRealmBrokerIdentityRequest.
type RegisterRealmBrokerIdentityResponse struct {
	Identity Identity `json:"identity"`
}

// BrokerChallengeRequest wraps Identifying information for the Identity initiating the challenge.
type BrokerChallengeRequest struct {
	RealmName string // The name of the realm the Identity is a member of.
	Action    string `json:"action"`   // The requested broker flow action to perform. Currently only challenge is supported.
	Username  string `json:"username"` // The name for the Identity initiating the challenge.
}

// EmailOTP wraps a one time password provided via an email challenge.
type EmailOTP struct {
	EmailOTP string `json:"email_otp"` // The one-time password from the email challenge issued.
}

// BrokerLoginRequest proof that the Identity has completed the broker challenge
// along with key material to encrypt the login response.
type BrokerLoginRequest struct {
	RealmName    string    // The name of the realm the Identity is a member of.
	Action       string    `json:"action"`        // The requested broker flow action to perform. Currently only login is supported
	NoteID       uuid.UUID `json:"note_id"`       // The ID of the recovery Note the email challenge was for.
	PublicKey    string    `json:"public_key"`    // The public key to use to encrypt the recovery note.
	SigningKey   string    `json:"signing_key"`   // The signing key to use to verify the integrity of the recovery note.
	AuthResponse EmailOTP  `json:"auth_response"` // The authentication material to allow the broker to access the seed material for the Identities recovery Note.
}

//  BrokerLoginResponse wraps the Note ID of the broker login recovery note.
type BrokerLoginResponse struct {
	RecoveryNoteID uuid.UUID `json:"transferId"`
}

// InternalClientForKeycloakUserResponse is the tozny client ID for a keycloak user
type InternalUpdateActiveForKeycloakUserID struct {
	Active bool `json:"active"`
}

// RealmOIDCPublicKey wraps parameters for a public key in JWK form used for OIDC flows for a given realm.
// JWK spec https://tools.ietf.org/html/rfc7517
// RSA key parameters https://www.gnupg.org/documentation/manuals/gcrypt-devel/RSA-key-parameters.html
type RealmOIDCPublicKey struct {
	KeyID string `json:"kid"`
	// Identifies the algorithm intended for use with the key.
	Algorithim string `json:"alg"`
	// The cryptographic algorithm family used with the key, such as "RSA" or "EC".
	KeyType string `json:"kty"`
	// RSA Public key exponent
	RSAExponent string `json:"e"`
	// RSA public modulus n.
	RSAModulus string `json:"n"`
	// The intended use of the public key, one of `sig`(nature) or `enc`(oding)
	Use string `json:"use"`
}

// ListRealmOIDCKeysResponse wraps a list of keys used for OIDC flows for a given realm.
type ListRealmOIDCKeysResponse struct {
	Keys []RealmOIDCPublicKey `json:"keys"`
}
