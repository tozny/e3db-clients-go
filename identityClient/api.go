package identityClient

// Realm represents the top level identity management resource for grouping and managing
// authentication and authorization of consuming application, identities, and sovereigns within a realm.
type Realm struct {
	ID        int64     `json:"id"`        // Service defined unique identifier for the realm.
	Name      string    `json:"name"`      // User defined realm identifier.
	AdminURL  string    `json:"admin_url"` // URL for realm administration console.
	Active    bool      `json:"active"`    // Whether the realm is active for applications and identities to consume.
	Sovereign Sovereign `json:"sovereign"` // The realm's sovereign.
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
	ToznyID      string            `json:"tozny_id"` // Tozny Client ID
	RealmID      int64             `json:"realm_id"`
	Name         string            `json:"name"`
	APIKeyID     string            `json:"api_key_id"`
	APIKeySecret string            `json:"api_secret_key"`
	PublicKeys   map[string]string `json:"public_key"`
	SigningKeys  map[string]string `json:"signing_key,omitemtpy"`
}

// RegisterIdentityRequest wraps parameters needed to create and register an identity with a realm.
type RegisterIdentityRequest struct {
	RealmRegistrationToken string   `json:"realm_registration_token"`
	RealmID                int64    `json:"realm_id"`
	Identity               Identity `json:"identity"`
}

// RegisterIdentityResponse wraps values returned from a register identity request.
type RegisterIdentityResponse struct {
	Identity Identity `json:"identity"`
}
