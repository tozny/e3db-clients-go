package identityClient

import (
	"time"

	"github.com/google/uuid"
)

const (
	ProtocolOIDC                                            = "openid-connect"
	ProtocolSAML                                            = "saml"
	LDAPProviderType                                        = "ldap"
	ActiveDirectoryProviderType                             = "ad"
	ProviderConnectionSimpleType                            = "simple"
	LDAPGroupProviderMapperType                             = "group-ldap-mapper"
	ProviderMapperReadOnlyMode                              = "READ_ONLY"
	ProviderMappperGroupsByMemberAttributeRetrievalStrategy = "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"
	ProviderTrustStoreLDAPOnlyMode                          = "ldapsOnly"
	ProviderDefaultMemberOfAttribute                        = "memberOf"
	SAMLIdentityProviderDescriptionFormat                   = "saml-idp-descriptor"
	SAMLKeycloakDescriptionFormat                           = "keycloak-saml"
	SAMLServiceProviderDescriptionFormat                    = "saml-sp-descriptor"
	SAMLKeycloakSubsystemDescriptionFormat                  = "keycloak-saml-subsystem"
	UserSessionNoteOIDCApplicationMapperType                = "oidc-user-session-note-mapper"
	UserAttributeOIDCApplicationMapperType                  = "oidc-user-attribute-mapper"
	GroupMembershipOIDCApplicationMapperType                = "oidc-group-membership-mapper"
	RoleListSAMLApplicationMapperType                       = "saml-role-list-mapper"
	UserPropertySAMLApplicationMapperType                   = "saml-user-property-mapper"
	ClaimJSONStringType                                     = "String"
	ClaimJSONLongType                                       = "long"
	ClaimJSONIntType                                        = "int"
	ClaimJSONBooleanType                                    = "boolean"
	BasicSAMLAttributeNameFormat                            = "Basic"
	UnspecifiedSAMLAttributeNameFormat                      = "Unspecified"
	URIReferenceSAMLAttributeNameFormat                     = "URI Reference"
	DefaultUMAProtectionApplicationRole                     = "uma_protection"
)

var (
	ValidSAMLDescriptionFormats = []string{
		SAMLIdentityProviderDescriptionFormat,
		SAMLKeycloakDescriptionFormat,
		SAMLServiceProviderDescriptionFormat,
		SAMLKeycloakSubsystemDescriptionFormat}
)

// Realm represents the top level identity management resource for grouping and managing
// authentication and authorization of consuming application, identities, and sovereigns within a realm.
type Realm struct {
	ID                    int64     `json:"id"`                                 // Service defined unique identifier for the realm.
	Name                  string    `json:"name"`                               // User defined realm identifier.
	Domain                string    `json:"domain"`                             // Case insensitive realm identifier
	AdminURL              string    `json:"admin_url"`                          // URL for realm administration console.
	Active                bool      `json:"active"`                             // Whether the realm is active for applications and identities to consume.
	Sovereign             Sovereign `json:"sovereign"`                          // The realm's sovereign.
	BrokerIdentityToznyID uuid.UUID `json:"broker_identity_tozny_id,omitempty"` // The Tozny Client ID associated with the Identity used to broker interactions between the realm and it's Identities. Will be empty if no realm broker Identity has been registered.
}

// RealmInfo represents the public information about a TozID realm
type RealmInfo struct {
	Name                  string    `json:"name"`
	BrokerIdentityToznyID uuid.UUID `json:"broker_id,omitempty"`
	Domain                string    `json:"domain"`
}

// PrivateRealmInfo represents the private information about a TozID realm
type PrivateRealmInfo struct {
	Name                  string    `json:"name"`
	BrokerIdentityToznyID uuid.UUID `json:"broker_id,omitempty"`
	Domain                string    `json:"domain"`
	SecretsEnabled        bool      `json:"secrets_enabled"`
	MFAAvailable          []string  `json:"mfa_available"`
	EmailLookupsEnabled   bool      `json:"email_lookups_enabled"`
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
	RealmName         string `json:"realm_name"`         // User defined realm identifier.
	SovereignName     string `json:"sovereign_name"`     // User defined identifier for the realm's sovereign.
	RegistrationToken string `json:"registration_token"` // Tozny Registration Token to associate with this realm.
}

// ListRealmsResponse wraps values returned from a list realms request.
type ListRealmsResponse struct {
	Realms []Realm `json:"realms"`
}

// Identity wraps a user of a given realm along with its authentication information.
type Identity struct {
	ID                    int64             `json:"id"`
	ToznyID               uuid.UUID         `json:"tozny_id"` // Tozny Client ID
	RealmID               int64             `json:"realm_id"`
	RealmName             string            `json:"realm_name"`
	Name                  string            `json:"name"`
	FirstName             string            `json:"first_name"`
	LastName              string            `json:"last_name"`
	Email                 string            `json:"email"`
	APIKeyID              string            `json:"api_key_id"`
	APIKeySecret          string            `json:"api_secret_key"`
	PublicKeys            map[string]string `json:"public_key"`
	PrivateEncryptionKeys map[string]string `json:"private_key"` // Never returned or held server side
	SigningKeys           map[string]string `json:"signing_key"`
	PrivateSigningKeys    map[string]string `json:"private_signing_key"` // Never returned or held server side
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

// IdentityLoginRequest wraps parameters needed to initiate an identity login session.
type IdentityLoginRequest struct {
	Username    string `json:"username"`
	RedirectURL string `json:"redirect_url"`
	RealmName   string `json:"realm_name"`
	AppName     string `json:"app_name"`
	LoginStyle  string `json:"login_style"`
}

// InitialLoginResponse is returned by the login endpoint on success
type InitialLoginResponse struct {
	Nonce         string `json:"nonce" schema:"nonce"`
	ClientID      string `json:"client_id" schema:"client_id"`
	ResponseType  string `json:"response_type" schema:"response_type"`
	Scope         string `json:"scope" schema:"scope"`
	RedirectURI   string `json:"redirect_uri" schema:"redirect_uri"`
	ResponseMode  string `json:"response_mode" schema:"response_mode"`
	State         string `json:"state" schema:"state"`
	Username      string `json:"username" schema:"username"`
	Target        string `json:"target" schema:"target"`
	AuthSessionID string `json:"auth_session_id" schema:"auth_session_id"`
	Federated     bool   `json:"federated" schema:"federated"`
}

// IdentitySessionRequestResponse is returned by the IdentitySesssionRequest. It contains data related to what additional
// actions are needed to create a session and how to create the session
type IdentitySessionRequestResponse struct {
	LoginAction     bool                   `json:"login_action"`
	LoginActionType string                 `json:"type"`
	ActionURL       string                 `json:"action_url"`
	Fields          map[string]string      `json:"fields"`
	Context         map[string]string      `json:"context"`
	ContentType     string                 `json:"content_type"`
	Message         SessionResponseMessage `json:"message"`
}

// SessionResponseMessage provides information reagarding the error status of login actions
// IsError is the most reliable source of information if the login action was successful or not
type SessionResponseMessage struct {
	Summary     string `json:"summary"`
	MessageType string `json:"type"`
	IsError     bool   `json:"error"`
	Warning     bool   `json:"warning"`
	Success     bool   `json:"success"`
}

// IdentityLoginRedirectRequest wraps parameters need to complete an identity login
type IdentityLoginRedirectRequest struct {
	RealmName     string `json:"realm_name"`
	SessionCode   string `json:"session_code"`
	Execution     string `json:"execution"`
	TabID         string `json:"tab_id"`
	ClientID      string `json:"client_id"`
	AuthSessionId string `json:"auth_session_id"`
}

// IdentityLoginRedirectResponse is returned by the IdentityLoginRedirect and contains access tokens for
// retrieving clients and sessions
type IdentityLoginRedirectResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Expiry      time.Time `json:"expiry"`
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

type UserChallengePushRequest struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Question string `json:"question"` // TODO:

	Username string `json:"username"`
	Realm    string `json:"realm"`
}

type InitiateUserChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	Username    string `json:"username"`
	Realm       string `json:"realm"`
}

type InitiateRegisterDeviceRequest struct {
	TempPublicKey           string `json:"temporary_public_key"`
	TempPublicEncryptionKey string `json:"temporary_public_encryption_key"`
}

// InitiateRegisterDeviceResponse
type InitiateRegisterDeviceResponse struct {
	RegistrationID      string `json:"registration_id"`
	Username            string `json:"username"`
	Realm               string `json:"realm"`
	EncryptedTOTPSecret string `json:"encrypted_totp_secret"`
}

type CompleteUserDeviceRegisterRequest struct {
	RegistrationID  string `json:"registration_id"`
	SignedChallenge string `json:"signed_challenge"`
	SignedTime      int64  `json:"sign_time"`

	OneSignalID     string `json:"one_signal_id"`     // Push notification client ID
	DeviceID        string `json:"device_id"`         // Unique device identifier
	DeviceName      string `json:"device_name"`       // Human readable device name
	DevicePublicKey string `json:"device_public_key"` // PublicKey to permanently stored PrivateKey on device
	TOTP            string `json:"totp"`
}

type CompleteChallengeRequest struct {
	ChallengeID     string `json:"challenge_id"`
	SignedChallenge string `json:"signed_challenge"` // signed challenge in the form of "{challenge}{timestamp}"
	SignedTime      int64  `json:"sign_time"`        // time challenge was signed
}

// LDAPCache wraps the LDAP JSON data passed between services for caching
type LDAPCache struct {
	// User's Keycloak ID
	ID string `json:"id,pk"`
	// User's LDAP UUID (assigned by the LDAP server)
	LDAPID string `json:"ldap_id"`
	// The domain query used to find the user in the LDAP server
	DN string `json:"dn"`
	// Relative Distinguished Name addresses this specific user relative to the DN
	RdnAttributeName string `json:"rdn_attribute_name"`
	// Used to define what type of LDAP object this is
	Classes []string `json:"classes"`
	// Information about the LDAP object in key -> multi-value pairs
	Attributes map[string][]string `json:"attributes"`
	// Attribute keys which should not be writable
	ReadOnlyAttributes []string `json:"read_only_attributes"`
	// A set of Keycloak group IDs the user had at the time of caching
	Groups []string `json:"groups"`
	// A set of Keycloak role IDs the user had at the time of caching
	Roles []string `json:"roles"`
}

// BrokerInfoResponse wraps the public info for the Tozny Hosted Broker
type ToznyHostedBrokerInfoResponse struct {
	ClientID         uuid.UUID `json:"client_id"`
	PublicKey        string    `json:"public_key"`
	PublicSigningKey string    `json:"public_signing_key"`
}

// CreateRealmGroupRequest wraps parameters for creating a realm group
type CreateRealmGroupRequest struct {
	RealmName string
	Group     Group
}

// DeleteRealmGroupRequest wraps parameters for deleting a realm group
type DeleteRealmGroupRequest struct {
	RealmName string
	GroupID   string
}

// DescribeRealmApplicationRequest wraps parameters for describing a realm application
type DescribeRealmGroupRequest = DeleteRealmGroupRequest

type ListRealmGroupsRequest struct {
	RealmName string
}

type ListRealmGroupsResponse struct {
	Groups []Group `json:"groups"`
}

// Application wraps API level values for a (client) application of a TozID realm.
type Application struct {
	// Server defined unique identifier for the application
	ID string `json:"id"`
	// Client facing identifier for the application
	ClientID string `json:"client_id"`
	// Human facing name of the application
	Name string `json:"name"`
	// Whether this consumer is allowed to authenticate and authorize identities
	Active bool `json:"active"`
	// Locations from which this application is allowed to consume realm data for authentication and authorization
	// (e.g. the login title has an allowed origin of * which is reflected in the CORS response)
	AllowedOrigins []string `json:"allowed_origins"`
	// What protocol (e.g. OpenIDConnect or SAML) is used to authenticate with the application
	Protocol     string                  `json:"protocol"`
	OIDCSettings ApplicationOIDCSettings `json:"application_oidc_settings"`
	SAMLSettings ApplicationSAMLSettings `json:"application_saml_settings"`
}

// ApplicationOIDCSettings wraps settings for an OpenID Connect enabled application
type ApplicationOIDCSettings struct {
	// (Optional) The URL to append to any relative URLs
	AccessType                string `json:"access_type"`
	RootURL                   string `json:"root_url"`
	StandardFlowEnabled       bool   `json:"standard_flow_enabled"`
	ImplicitFlowEnabled       bool   `json:"implicit_flow_enabled"`
	DirectAccessGrantsEnabled bool   `json:"direct_access_grants_enabled"`
	BaseURL                   string `json:"base_url"`
}

// ApplicationSAMLSettings wraps settings for a SAML enabled application
type ApplicationSAMLSettings struct {
	// (Optional) URL used for every binding to both the SP's Assertion Consumer and Single Logout Services.
	// This can be individually overridden for each binding and service
	DefaultEndpoint                        string `json:"default_endpoint"`
	IncludeAuthnStatement                  bool   `json:"include_authn_statement"`
	IncludeOneTimeUseCondition             bool   `json:"include_one_time_use_condition"`
	SignDocuments                          bool   `json:"sign_documents"`
	SignAssertions                         bool   `json:"sign_assertions"`
	ClientSignatureRequired                bool   `json:"client_signature_required"`
	ForcePostBinding                       bool   `json:"force_post_binding"`
	ForceNameIDFormat                      bool   `json:"force_name_id_format"`
	NameIDFormat                           string `json:"name_id_format"`
	IDPInitiatedSSOURLName                 string `json:"idp_initiated_sso_url_name"`
	AssertionConsumerServicePOSTBindingURL string `json:"assertion_consumer_service_post_binding_url"`
}

// CreateRealmApplicationRequest wraps parameters for creating a realm application
type CreateRealmApplicationRequest struct {
	RealmName   string
	Application Application
}

// DeleteRealmApplicationRequest wraps parameters for deleting a realm application
type DeleteRealmApplicationRequest struct {
	RealmName     string
	ApplicationID string
}

// DescribeRealmApplicationRequest wraps parameters for describing a realm application
type DescribeRealmApplicationRequest = DeleteRealmApplicationRequest

// ListRealmApplicationsResponse wraps the listing of applications for a realm
type ListRealmApplicationsResponse struct {
	Applications []Application `json:"applications"`
}

type ApplicationRole = Role

type CreateRealmApplicationRoleRequest struct {
	RealmName       string
	ApplicationID   string
	ApplicationRole ApplicationRole
}

type DeleteRealmApplicationRoleRequest struct {
	RealmName           string
	ApplicationID       string
	ApplicationRoleName string
}

type DescribeRealmApplicationRoleRequest = DeleteRealmApplicationRoleRequest

type ListRealmApplicationRolesRequest struct {
	RealmName     string
	ApplicationID string
}

type ListRealmApplicationRolesResponse struct {
	ApplicationRoles []ApplicationRole `json:"application_roles"`
}

// Provider wraps values related to a realm identity provider
type Provider struct {
	ID                 string                     `json:"id"`
	Type               string                     `json:"type"`
	Name               string                     `json:"name"`
	Active             bool                       `json:"active"`
	Priority           int                        `json:"priority"`
	ImportIdentities   bool                       `json:"import_identities"`
	SyncMode           string                     `json:"sync_mode"`
	SyncOnRegistration bool                       `json:"sync_on_registration"`
	ConnectionSettings ProviderConnectionSettings `json:"connection_settings"`
}

// ProviderConnectionSettings wraps settings for connecting a realm to an identity provider
type ProviderConnectionSettings struct {
	Type                  string   `json:"type"`
	IdentityNameAttribute string   `json:"identity_name_attribute"`
	RDNAttribute          string   `json:"rdn_attribute"`
	UUIDAttribute         string   `json:"uuid_attribute"`
	IdentityObjectClasses []string `json:"identity_object_classes"`
	ConnectionURL         string   `json:"connection_url"`
	IdentityDN            string   `json:"identity_dn"`
	AuthenticationType    string   `json:"authentication_type"`
	BindDN                string   `json:"bind_dn"`
	BindCredential        string   `json:"bind_credential"`
	SearchScope           int      `json:"search_scope"`
	TrustStoreSPIMode     string   `json:"truststore_spi_mode"`
	ConnectionPooling     bool     `json:"connection_pooling"`
	Pagination            bool     `json:"pagination"`
}

// CreateRealmProviderRequest wraps parameters for creating a realm provider
type CreateRealmProviderRequest struct {
	RealmName string
	Provider  Provider
}

// DeleteRealmProviderRequest wraps parameters for deleting a realm provider
type DeleteRealmProviderRequest struct {
	RealmName  string
	ProviderID string
}

// DescribeRealmProviderRequest wraps parameters for describing a realm provider
type DescribeRealmProviderRequest = DeleteRealmProviderRequest

// ListRealmProvidersResponse wraps the listing of providers for a realm
type ListRealmProvidersResponse struct {
	Providers []Provider `json:"providers"`
}

// Provider wraps values related to a realm identity provider mapper
type ProviderMapper struct {
	ID                              string   `json:"id"`
	Type                            string   `json:"type"`
	Name                            string   `json:"name"`
	GroupsDN                        string   `json:"groups_dn"`
	GroupNameAttribute              string   `json:"group_name_attribute"`
	GroupObjectClasses              []string `json:"group_object_classes"`
	PreserveGroupInheritance        bool     `json:"preserve_group_inheritance"`
	IgnoreMissingGroups             bool     `json:"ignore_missing_groups"`
	MemberOfAttribute               string   `json:"member_of_attribute"`
	MembershipAttribute             string   `json:"membership_attribute"`
	MembershipAttributeType         string   `json:"membership_attribute_type"`
	MembershipIdentityAttribute     string   `json:"membership_identity_attribute"`
	Mode                            string   `json:"mode"`
	IdentityGroupsRetrievalStrategy string   `json:"identity_groups_retrieval_strategy"`
	DropMissingGroupsOnSync         bool     `json:"drop_missing_groups_on_sync"`
}

// CreateRealmProviderMapperRequest wraps parameters for creating a realm provider mapper
type CreateRealmProviderMapperRequest struct {
	RealmName      string
	ProviderID     string
	ProviderMapper ProviderMapper
}

// DeleteRealmProviderMapperRequest wraps parameters for deleting a realm provider's mapper
type DeleteRealmProviderMapperRequest struct {
	RealmName        string
	ProviderID       string
	ProviderMapperID string
}

// DescribeRealmProviderMapperRequest wraps parameters for describing a realm provider's mapper
type DescribeRealmProviderMapperRequest = DeleteRealmProviderMapperRequest

// ListRealmProviderMappersRequest wraps parameters for listing the mappers for a realm provider
type ListRealmProviderMappersRequest struct {
	RealmName  string
	ProviderID string
}

// ListRealmProviderMappersResponse wraps the listing of provider mappers for a realm's provider
type ListRealmProviderMappersResponse struct {
	ProviderMappers []ProviderMapper `json:"provider_mappers"`
}

// BasicIdentity wraps a subset of information about an identity within a given realm
type BasicIdentity struct {
	ID        string `json:"subject_id"` // Keycloak User UUID
	Name      string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Active    bool   `json:"active"`
	Federated bool   `json:"federated"`
}

// ListIdentitiesRequest wraps the data to request a list of identities in a realm
type ListIdentitiesRequest struct {
	RealmName string
	First     int
	Max       int
}

// ListIdentitiesResponse wraps the listing of realm identities and includes a next token
type ListIdentitiesResponse struct {
	Identities []BasicIdentity `json:"identities"`
	Next       int             `json:"next"`
}

// IdentityDetails wraps the detailed information about an identity, including roles and groups
type IdentityDetails struct {
	ID         string              `json:"subject_id"`
	Name       string              `json:"username"`
	Email      string              `json:"email"`
	FirstName  string              `json:"first_name"`
	LastName   string              `json:"last_name"`
	Active     bool                `json:"active"`
	Federated  bool                `json:"federated"`
	Roles      RoleMapping         `json:"roles"`
	Groups     []Group             `json:"groups"`
	Attributes map[string][]string `json:"attributes"`
}

// RealmIdentityRequest wraps a realm name and identity ID
type RealmIdentityRequest struct {
	RealmName  string
	IdentityID string
}

// UpdateIdentityGroupMembershipRequest wraps a realm name and set of role IDs for a realm
type UpdateIdentityGroupMembershipRequest struct {
	RealmName  string   `json:"-"`
	IdentityID string   `json:"-"`
	Groups     []string `json:"groups"`
}

// RoleMapping wraps a full set of roles for a realm and its clients
type RoleMapping struct {
	ClientRoles map[string][]Role `json:"client"`
	RealmRoles  []Role            `json:"realm"`
}

// Role wraps a single role representation in a realm
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"client_role"`
	ContainerID string `json:"container_id"`
}

// Group wraps a single group representation in a realm
type Group struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Path       string              `json:"path"`
	Attributes map[string][]string `json:"attributes"`
	SubGroups  []Group             `json:"subGroups"`
}

// ListGroupRoleMappingsRequest wraps parameters for
// retrieving the role mapping for a group
type ListGroupRoleMappingsRequest struct {
	RealmName string
	GroupID   string
}

// AddGroupRoleMappingsRequest wraps request parameters for
// adding role mappings to a group.
type AddGroupRoleMappingsRequest struct {
	RealmName   string
	GroupID     string
	RoleMapping RoleMapping
}

// RemoveGroupRoleMappingsRequest wraps request parameters for
// removing role mappings from a group.
type RemoveGroupRoleMappingsRequest = AddGroupRoleMappingsRequest

// UpdateGroupListRequest wraps a realm name and set of role IDs for a realm
type UpdateGroupListRequest struct {
	RealmName string   `json:"-"`
	Groups    []string `json:"groups"`
}

// CreateRealmRoleRequest wraps parameters for creating a realm role
type CreateRealmRoleRequest struct {
	RealmName string
	Role      Role
}

// DeleteRealmRoleRequest wraps parameters for deleting a realm role
type DeleteRealmRoleRequest struct {
	RealmName string
	RoleID    string
}

// DescribeRealmRoleRequest wraps parameters for describing a realm role
type DescribeRealmRoleRequest = DeleteRealmRoleRequest

// ListRealmRolesResponse wraps the listing of roles for a realm
type ListRealmRolesResponse struct {
	Roles []Role `json:"roles"`
}

// FetchApplicationSecretRequest wraps parameters for retrieving the OIDC client secret for an application
type FetchApplicationSecretRequest struct {
	RealmName     string
	ApplicationID string
}

// ApplicationSecret wraps values for the configured OIDC client secret for an Application
type ApplicationSecret struct {
	Secret string `json:"secret"`
}

type InternalDeleteIdentitiesByProviderRequest struct {
	RealmName  string
	ProviderID uuid.UUID
}

// FetchApplicationSAMLDescriptionRequest wraps parameters for retrieving the SAML client XML configuration for an application
type FetchApplicationSAMLDescriptionRequest struct {
	RealmName     string
	ApplicationID string
	Format        string
}

// ApplicationMapper wraps related values related to an application mapper for auth flows of a given protocol.
type ApplicationMapper struct {
	// The UUID assigned to the application mapper
	ID string `json:"id"`
	// User defined name for the application mapper
	Name string `json:"name"`
	// The identity protocol that this mapper will be applied to flows of
	Protocol string `json:"protocol"`
	// The category of data this mapper is applied to
	MapperType string `json:"mapper_type"`
	// Name of stored user session note within the UserSessionModel.note map
	UserSessionNote string `json:"user_session_note"`
	// Name of stored user attribute within the UserModel.attribute map
	UserAttribute string `json:"user_attribute"`
	// Whether or not to map in the full group path in tokens when mapping groups into tokens
	FullPath bool `json:"full_path"`
	// Name of the claim to insert into the token. This can be a fully qualified name like 'address.street'. In this case, a nested json object will be created. To prevent nesting and use dot literally, escape the dot with backslash (\.)
	TokenClaimName string `json:"token_claim_name"`
	// JSON type that should be used to populate the json claim in the token
	ClaimJSONType string `json:"claim_json_type"`
	// Indicates if the claim should be added to the access token
	AddToIDToken bool `json:"add_to_id_token"`
	// Indicates if the claim should be added to the access token
	AddToAccessToken bool `json:"add_to_access_token"`
	// Indicates if the claim should be added to the user info
	AddToUserInfo bool `json:"add_to_user_info"`
	// Indicates if attribute supports multiple values. If true, then the list of all values of this attribute will be set as claim. If false, then just first value will be set as claim
	Multivalued bool `json:"multivalued"`
	// Indicates if attribute values should be aggregated with the group attributes. If using OpenID Connect mapper the multivalued option needs to be enabled too in order to get all the values. Duplicated values are discarded and the order of values is not guaranteed with this option
	AggregateAttributeValues bool `json:"aggregate_attribute_values"`
	// Name of the SAML attribute you want to put your roles into. i.e. 'Role', 'memberOf'
	RoleAttributeName string `json:"role_attribute_name"`
	// Name of the property method in the UserModel interface. For example, a value of 'email' would reference the UserModel.getEmail() method
	Property string `json:"property"`
	// Standard SAML attribute setting. An optional, more human-readable form of the attribute's name that can be provided if the actual attribute name is cryptic
	FriendlyName string `json:"friendly_name"`
	// Name of the SAML attribute that should be used for mapping an identities name
	SAMLAttributeName string `json:"saml_attribute_name"`
	// Format to use for the name attribute for the SAML protocol
	SAMLAttributeNameFormat string `json:"saml_attribute_name_format"`
	// If true, all roles will be stored under one attribute with multiple attribute values
	SingleRoleAttribute bool `json:"single_role_attribute"`
}

// ApplicationSAMLDescription wraps values for the SAML XML description for an Application
type ApplicationSAMLDescription struct {
	// Raw XML description for a SAML application
	Description string `json:"description"`
}

// CreateRealmApplicationMapperRequest wraps parameters for creating a realm application mapper
type CreateRealmApplicationMapperRequest struct {
	RealmName         string
	ApplicationID     string
	ApplicationMapper ApplicationMapper
}

// DeleteRealmApplicationMapperRequest wraps parameters for deleting a realm application mapper
type DeleteRealmApplicationMapperRequest struct {
	RealmName           string
	ApplicationID       string
	ApplicationMapperID string
}

// DescribeRealmApplicationMapperRequest wraps parameters for describing a realm application mapper
type DescribeRealmApplicationMapperRequest = DeleteRealmApplicationMapperRequest

// ListRealmApplicationMappersRequest wraps parameters for listing the protocol mappers for an application
type ListRealmApplicationMappersRequest struct {
	RealmName     string
	ApplicationID string
}

// ListRealmApplicationMappersResponse wraps the listing of application mappers for an application
type ListRealmApplicationMappersResponse struct {
	ApplicationMappers []ApplicationMapper `json:"application_mappers"`
}

// SearchRealmIdentitiesResponse wraps matching identities in the given realm for the search criteria (if any)
type SearchRealmIdentitiesResponse struct {
	SearchCriteria                string                        `json:"search_criteria"`
	SearchedIdentitiesInformation []SearchIdentitiesInformation `json:"searched_identities_information"`
}

// SearchRealmIdentitiesRequest wraps the search criteria to use for retrieving matching Identities from a given realm
type SearchRealmIdentitiesRequest struct {
	RealmName         string
	IdentityEmails    []string    `json:"identity_emails"`
	IdentityUsernames []string    `json:"identity_usernames"`
	IdentityClientIDs []uuid.UUID `json:"identity_client_ids"`
}

// SearchIdentitiesInformation wraps the information that is pulled from a user during a look up
type SearchIdentitiesInformation struct {
	RealmUsername string    `json:"realm_username"`
	RealmEmail    string    `json:"realm_email"`
	UserID        string    `json:"user_id"`
	ClientID      uuid.UUID `json:"client_id"`
}

// RealmSettingsUpdateRequest wraps the setting available for realm admins to update
type RealmSettingsUpdateRequest struct {
	SecretsEnabled      *bool     `json:"secrets_enabled,omitempty"`
	MFAAvailable        *[]string `json:"mfa_available,omitempty"`
	EmailLookupsEnabled *bool     `json:"email_lookups_enabled,omitempty"`
}
