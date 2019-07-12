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

// CreateRealmRequest wraps parameters needed request creation of a realm.
type CreateRealmRequest struct {
	RealmName     string `json:"realm_name"`     // User defined realm identifier.
	SovereignName string `json:"sovereign_name"` // User defined identifier for the realm's sovereign.
}

// ListRealmsResponse wraps values returned from a list realms request.
type ListRealmsResponse struct {
	Realms []Realm `json:"realms"`
}
