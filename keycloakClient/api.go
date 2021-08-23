package keycloakClient

import (
	"net/http"
	"net/url"
	"time"
)

// TokenInfo represents a full oAuth2 JWT token response with expiration and refresh.
type TokenInfo struct {
	TokenType      string
	AccessToken    string
	Expires        time.Time
	RefreshToken   string
	RefreshExpires time.Time
	refresher      *time.Timer
}

// Client is the keycloak client which contains a map of current tokens.
type Client struct {
	tokenProviderURL *url.URL
	apiURL           *url.URL
	httpClient       *http.Client
	tokens           map[string]*TokenInfo
}

// Config is the http config used to create a client.
type Config struct {
	AddrTokenProvider string
	AddrAPI           string
	Timeout           time.Duration
}

// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token in JSON form.
type tokenJSON struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int32  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int32  `json:"refresh_expires_in"`
}

type AuthenticationFlowRepresentation struct {
	Alias                    *string                                        `json:"alias,omitempty"`
	AuthenticationExecutions *[]AuthenticationExecutionExportRepresentation `json:"authenticationExecutions,omitempty"`
	BuiltIn                  *bool                                          `json:"builtIn,omitempty"`
	Description              *string                                        `json:"description,omitempty"`
	Id                       *string                                        `json:"id,omitempty"`
	ProviderId               *string                                        `json:"providerId,omitempty"`
	TopLevel                 *bool                                          `json:"topLevel,omitempty"`
}

type AuthenticationExecutionExportRepresentation struct {
	Authenticator       *string `json:"authenticator,omitempty"`
	AuthenticatorConfig *string `json:"authenticatorConfig,omitempty"`
	AuthenticatorFlow   *bool   `json:"authenticatorFlow,omitempty"`
	AutheticatorFlow    *bool   `json:"autheticatorFlow,omitempty"`
	FlowAlias           *string `json:"flowAlias,omitempty"`
	Priority            *int32  `json:"priority,omitempty"`
	Requirement         *string `json:"requirement,omitempty"`
	UserSetupAllowed    *bool   `json:"userSetupAllowed,omitempty"`
}

type AuthenticatorConfigRepresentation struct {
	Alias  *string                 `json:"alias,omitempty"`
	Config *map[string]interface{} `json:"config,omitempty"`
	Id     *string                 `json:"id,omitempty"`
}

type ClientTemplateRepresentation struct {
	Attributes                *map[string]interface{}         `json:"attributes,omitempty"`
	BearerOnly                *bool                           `json:"bearerOnly,omitempty"`
	ConsentRequired           *bool                           `json:"consentRequired,omitempty"`
	Description               *string                         `json:"description,omitempty"`
	DirectAccessGrantsEnabled *bool                           `json:"directAccessGrantsEnabled,omitempty"`
	FrontchannelLogout        *bool                           `json:"frontchannelLogout,omitempty"`
	FullScopeAllowed          *bool                           `json:"fullScopeAllowed,omitempty"`
	Id                        *string                         `json:"id,omitempty"`
	ImplicitFlowEnabled       *bool                           `json:"implicitFlowEnabled,omitempty"`
	Name                      *string                         `json:"name,omitempty"`
	Protocol                  *string                         `json:"protocol,omitempty"`
	ProtocolMappers           *[]ProtocolMapperRepresentation `json:"protocolMappers,omitempty"`
	PublicClient              *bool                           `json:"publicClient,omitempty"`
	ServiceAccountsEnabled    *bool                           `json:"serviceAccountsEnabled,omitempty"`
	StandardFlowEnabled       *bool                           `json:"standardFlowEnabled,omitempty"`
}

type ProtocolMapperRepresentation struct {
	Config          *map[string]interface{} `json:"config,omitempty"`
	ConsentRequired *bool                   `json:"consentRequired,omitempty"`
	ConsentText     *string                 `json:"consentText,omitempty"`
	Id              *string                 `json:"id,omitempty"`
	Name            *string                 `json:"name,omitempty"`
	Protocol        *string                 `json:"protocol,omitempty"`
	ProtocolMapper  *string                 `json:"protocolMapper,omitempty"`
}

type PolicyRepresentation struct {
	Config           *map[string]interface{} `json:"config,omitempty"`
	DecisionStrategy *string                 `json:"decisionStrategy,omitempty"`
	Description      *string                 `json:"description,omitempty"`
	Id               *string                 `json:"id,omitempty"`
	Logic            *string                 `json:"logic,omitempty"`
	Name             *string                 `json:"name,omitempty"`
	Policies         *[]string               `json:"policies,omitempty"`
	Resources        *[]string               `json:"resources,omitempty"`
	Scopes           *[]string               `json:"scopes,omitempty"`
	Type             *string                 `json:"type,omitempty"`
}

type ScopeRepresentation struct {
	IconUri   *string                   `json:"iconUri,omitempty"`
	Id        *string                   `json:"id,omitempty"`
	Name      *string                   `json:"name,omitempty"`
	Policies  *[]PolicyRepresentation   `json:"policies,omitempty"`
	Resources *[]ResourceRepresentation `json:"resources,omitempty"`
}

type ResourceServerRepresentation struct {
	AllowRemoteResourceManagement *bool                     `json:"allowRemoteResourceManagement,omitempty"`
	ClientId                      *string                   `json:"clientId,omitempty"`
	Id                            *string                   `json:"id,omitempty"`
	Name                          *string                   `json:"name,omitempty"`
	Policies                      *[]PolicyRepresentation   `json:"policies,omitempty"`
	PolicyEnforcementMode         *string                   `json:"policyEnforcementMode,omitempty"`
	Resources                     *[]ResourceRepresentation `json:"resources,omitempty"`
	Scopes                        *[]ScopeRepresentation    `json:"scopes,omitempty"`
}

type ResourceOwnerRepresentation struct {
	Id   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

type ResourceRepresentation struct {
	Id          *string                      `json:"id,omitempty"`
	Icon_uri    *string                      `json:"icon_uri,omitempty"`
	Name        *string                      `json:"name,omitempty"`
	Owner       *ResourceOwnerRepresentation `json:"owner,omitempty"`
	Policies    *[]PolicyRepresentation      `json:"policies,omitempty"`
	Scopes      *[]ScopeRepresentation       `json:"scopes,omitempty"`
	Type        *string                      `json:"type,omitempty"`
	TypedScopes *[]ScopeRepresentation       `json:"typedScopes,omitempty"`
	Uri         *string                      `json:"uri,omitempty"`
}

type ClientRepresentation struct {
	Access                             *map[string]interface{}         `json:"access,omitempty"`
	AdminUrl                           *string                         `json:"adminUrl,omitempty"`
	Attributes                         *map[string]interface{}         `json:"attributes,omitempty"`
	AuthorizationServicesEnabled       *bool                           `json:"authorizationServicesEnabled,omitempty"`
	AuthorizationSettings              *ResourceServerRepresentation   `json:"authorizationSettings,omitempty"`
	BaseUrl                            *string                         `json:"baseUrl,omitempty"`
	BearerOnly                         *bool                           `json:"bearerOnly,omitempty"`
	ClientAuthenticatorType            *string                         `json:"clientAuthenticatorType,omitempty"`
	ClientId                           *string                         `json:"clientId,omitempty"`
	ClientTemplate                     *string                         `json:"clientTemplate,omitempty"`
	ConsentRequired                    *bool                           `json:"consentRequired,omitempty"`
	DefaultRoles                       *[]string                       `json:"defaultRoles,omitempty"`
	Description                        *string                         `json:"description,omitempty"`
	DirectAccessGrantsEnabled          *bool                           `json:"directAccessGrantsEnabled,omitempty"`
	Enabled                            *bool                           `json:"enabled,omitempty"`
	FrontchannelLogout                 *bool                           `json:"frontchannelLogout,omitempty"`
	FullScopeAllowed                   *bool                           `json:"fullScopeAllowed,omitempty"`
	Id                                 *string                         `json:"id,omitempty"`
	ImplicitFlowEnabled                *bool                           `json:"implicitFlowEnabled,omitempty"`
	Name                               *string                         `json:"name,omitempty"`
	NodeReRegistrationTimeout          *int32                          `json:"nodeReRegistrationTimeout,omitempty"`
	NotBefore                          *int32                          `json:"notBefore,omitempty"`
	Protocol                           *string                         `json:"protocol,omitempty"`
	ProtocolMappers                    *[]ProtocolMapperRepresentation `json:"protocolMappers,omitempty"`
	PublicClient                       *bool                           `json:"publicClient,omitempty"`
	RedirectUris                       *[]string                       `json:"redirectUris,omitempty"`
	RegisteredNodes                    *map[string]interface{}         `json:"registeredNodes,omitempty"`
	RegistrationAccessToken            *string                         `json:"registrationAccessToken,omitempty"`
	RootUrl                            *string                         `json:"rootUrl,omitempty"`
	Secret                             *string                         `json:"secret,omitempty"`
	ServiceAccountsEnabled             *bool                           `json:"serviceAccountsEnabled,omitempty"`
	StandardFlowEnabled                *bool                           `json:"standardFlowEnabled,omitempty"`
	SurrogateAuthRequired              *bool                           `json:"surrogateAuthRequired,omitempty"`
	UseTemplateConfig                  *bool                           `json:"useTemplateConfig,omitempty"`
	UseTemplateMappers                 *bool                           `json:"useTemplateMappers,omitempty"`
	UseTemplateScope                   *bool                           `json:"useTemplateScope,omitempty"`
	WebOrigins                         *[]string                       `json:"webOrigins,omitempty"`
	AuthenticationFlowBindingOverrides *map[string]interface{}         `json:"authenticationFlowBindingOverrides,omitempty"`
}

type MultivaluedHashMap struct {
	Empty      *bool  `json:"empty,omitempty"`
	LoadFactor *int32 `json:"loadFactor,omitempty"`
	Threshold  *int32 `json:"threshold,omitempty"`
}

type UserConsentRepresentation struct {
	ClientId               *string                 `json:"clientId,omitempty"`
	CreatedDate            *int64                  `json:"createdDate,omitempty"`
	GrantedClientRoles     *map[string]interface{} `json:"grantedClientRoles,omitempty"`
	GrantedProtocolMappers *map[string]interface{} `json:"grantedProtocolMappers,omitempty"`
	GrantedRealmRoles      *[]string               `json:"grantedRealmRoles,omitempty"`
	LastUpdatedDate        *int64                  `json:"lastUpdatedDate,omitempty"`
}

type CredentialRepresentation struct {
	Id                *string              `json:"id,omitempty"`
	Algorithm         *string              `json:"algorithm,omitempty"`
	Config            *map[string][]string `json:"config,omitempty"`
	Counter           *int32               `json:"counter,omitempty"`
	CreatedDate       *int64               `json:"createdDate,omitempty"`
	Device            *string              `json:"device,omitempty"`
	Digits            *int32               `json:"digits,omitempty"`
	HashIterations    *int32               `json:"hashIterations,omitempty"`
	HashedSaltedValue *string              `json:"hashedSaltedValue,omitempty"`
	Period            *int32               `json:"period,omitempty"`
	Salt              *string              `json:"salt,omitempty"`
	Temporary         *bool                `json:"temporary,omitempty"`
	Type              *string              `json:"type,omitempty"`
	Value             *string              `json:"value,omitempty"`
}

type FederatedIdentityRepresentation struct {
	IdentityProvider *string `json:"identityProvider,omitempty"`
	UserId           *string `json:"userId,omitempty"`
	UserName         *string `json:"userName,omitempty"`
}

type UserRepresentation struct {
	Access                     *map[string]bool                   `json:"access,omitempty"`
	Attributes                 *map[string][]string               `json:"attributes,omitempty"`
	ClientConsents             *[]UserConsentRepresentation       `json:"clientConsents,omitempty"`
	ClientRoles                *map[string][]string               `json:"clientRoles,omitempty"`
	CreatedTimestamp           *int64                             `json:"createdTimestamp,omitempty"`
	Credentials                *[]CredentialRepresentation        `json:"credentials,omitempty"`
	DisableableCredentialTypes *[]string                          `json:"disableableCredentialTypes,omitempty"`
	Email                      *string                            `json:"email,omitempty"`
	EmailVerified              *bool                              `json:"emailVerified,omitempty"`
	Enabled                    *bool                              `json:"enabled,omitempty"`
	FederatedIdentities        *[]FederatedIdentityRepresentation `json:"federatedIdentities,omitempty"`
	FederationLink             *string                            `json:"federationLink,omitempty"`
	FirstName                  *string                            `json:"firstName,omitempty"`
	Groups                     *[]string                          `json:"groups,omitempty"`
	Id                         *string                            `json:"id,omitempty"`
	LastName                   *string                            `json:"lastName,omitempty"`
	NotBefore                  *int32                             `json:"notBefore,omitempty"`
	Origin                     *string                            `json:"origin,omitempty"`
	RealmRoles                 *[]string                          `json:"realmRoles,omitempty"`
	RequiredActions            *[]string                          `json:"requiredActions,omitempty"`
	Self                       *string                            `json:"self,omitempty"`
	ServiceAccountClientId     *string                            `json:"serviceAccountClientId,omitempty"`
	Username                   *string                            `json:"username,omitempty"`
}

type GroupRepresentation struct {
	Access      *map[string]interface{} `json:"access,omitempty"`
	Attributes  *map[string]interface{} `json:"attributes,omitempty"`
	ClientRoles *map[string]interface{} `json:"clientRoles,omitempty"`
	Id          *string                 `json:"id,omitempty"`
	Name        *string                 `json:"name,omitempty"`
	Path        *string                 `json:"path,omitempty"`
	RealmRoles  *[]string               `json:"realmRoles,omitempty"`
	SubGroups   *[]GroupRepresentation  `json:"subGroups,omitempty"`
}

type IdentityProviderMapperRepresentation struct {
	Config                 *map[string]interface{} `json:"config,omitempty"`
	Id                     *string                 `json:"id,omitempty"`
	IdentityProviderAlias  *string                 `json:"identityProviderAlias,omitempty"`
	IdentityProviderMapper *string                 `json:"identityProviderMapper,omitempty"`
	Name                   *string                 `json:"name,omitempty"`
}

type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool                   `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string                 `json:"alias,omitempty"`
	Config                    *map[string]interface{} `json:"config,omitempty"`
	DisplayName               *string                 `json:"displayName,omitempty"`
	Enabled                   *bool                   `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string                 `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalId                *string                 `json:"internalId,omitempty"`
	LinkOnly                  *bool                   `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string                 `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderId                *string                 `json:"providerId,omitempty"`
	StoreToken                *bool                   `json:"storeToken,omitempty"`
	TrustEmail                *bool                   `json:"trustEmail,omitempty"`
}

type RequiredActionProviderRepresentation struct {
	Alias         *string                 `json:"alias,omitempty"`
	Config        *map[string]interface{} `json:"config,omitempty"`
	DefaultAction *bool                   `json:"defaultAction,omitempty"`
	Enabled       *bool                   `json:"enabled,omitempty"`
	Name          *string                 `json:"name,omitempty"`
	ProviderId    *string                 `json:"providerId,omitempty"`
	Priority      *int                    `json:"priority,omitempty"`
}

type RoleRepresentationComposites struct {
	Client *map[string]interface{} `json:"client,omitempty"`
	Realm  *[]string               `json:"realm,omitempty"`
}

type RoleRepresentation struct {
	ClientRole         *bool                         `json:"clientRole,omitempty"`
	Composite          *bool                         `json:"composite,omitempty"`
	Composites         *RoleRepresentationComposites `json:"composites,omitempty"`
	ContainerId        *string                       `json:"containerId,omitempty"`
	Description        *string                       `json:"description,omitempty"`
	Id                 *string                       `json:"id,omitempty"`
	Name               *string                       `json:"name,omitempty"`
	ScopeParamRequired *bool                         `json:"scopeParamRequired,omitempty"`
}

type RolesRepresentation struct {
	Client *map[string]interface{} `json:"client,omitempty"`
	Realm  *[]RoleRepresentation   `json:"realm,omitempty"`
}

type ScopeMappingRepresentation struct {
	Client         *string   `json:"client,omitempty"`
	ClientTemplate *string   `json:"clientTemplate,omitempty"`
	Roles          *[]string `json:"roles,omitempty"`
	Self           *string   `json:"self,omitempty"`
}

type RealmRepresentation struct {
	AccessCodeLifespan                  *int32                                  `json:"accessCodeLifespan,omitempty"`
	AccessCodeLifespanLogin             *int32                                  `json:"accessCodeLifespanLogin,omitempty"`
	AccessCodeLifespanUserAction        *int32                                  `json:"accessCodeLifespanUserAction,omitempty"`
	AccessTokenLifespan                 *int32                                  `json:"accessTokenLifespan,omitempty"`
	AccessTokenLifespanForImplicitFlow  *int32                                  `json:"accessTokenLifespanForImplicitFlow,omitempty"`
	AccountTheme                        *string                                 `json:"accountTheme,omitempty"`
	ActionTokenGeneratedByAdminLifespan *int32                                  `json:"actionTokenGeneratedByAdminLifespan,omitempty"`
	ActionTokenGeneratedByUserLifespan  *int32                                  `json:"actionTokenGeneratedByUserLifespan,omitempty"`
	AdminEventsDetailsEnabled           *bool                                   `json:"adminEventsDetailsEnabled,omitempty"`
	AdminEventsEnabled                  *bool                                   `json:"adminEventsEnabled,omitempty"`
	AdminTheme                          *string                                 `json:"adminTheme,omitempty"`
	Attributes                          *map[string]interface{}                 `json:"attributes,omitempty"`
	AuthenticationFlows                 *[]AuthenticationFlowRepresentation     `json:"authenticationFlows,omitempty"`
	AuthenticatorConfig                 *[]AuthenticatorConfigRepresentation    `json:"authenticatorConfig,omitempty"`
	BrowserFlow                         *string                                 `json:"browserFlow,omitempty"`
	BrowserSecurityHeaders              *map[string]interface{}                 `json:"browserSecurityHeaders,omitempty"`
	BruteForceProtected                 *bool                                   `json:"bruteForceProtected,omitempty"`
	ClientAuthenticationFlow            *string                                 `json:"clientAuthenticationFlow,omitempty"`
	ClientScopeMappings                 *map[string]interface{}                 `json:"clientScopeMappings,omitempty"`
	ClientTemplates                     *[]ClientTemplateRepresentation         `json:"clientTemplates,omitempty"`
	Clients                             *[]ClientRepresentation                 `json:"clients,omitempty"`
	Components                          *MultivaluedHashMap                     `json:"components,omitempty"`
	DefaultGroups                       *[]string                               `json:"defaultGroups,omitempty"`
	DefaultLocale                       *string                                 `json:"defaultLocale,omitempty"`
	DefaultRoles                        *[]string                               `json:"defaultRoles,omitempty"`
	DirectGrantFlow                     *string                                 `json:"directGrantFlow,omitempty"`
	DisplayName                         *string                                 `json:"displayName,omitempty"`
	DisplayNameHtml                     *string                                 `json:"displayNameHtml,omitempty"`
	DockerAuthenticationFlow            *string                                 `json:"dockerAuthenticationFlow,omitempty"`
	DuplicateEmailsAllowed              *bool                                   `json:"duplicateEmailsAllowed,omitempty"`
	EditUsernameAllowed                 *bool                                   `json:"editUsernameAllowed,omitempty"`
	EmailTheme                          *string                                 `json:"emailTheme,omitempty"`
	Enabled                             *bool                                   `json:"enabled,omitempty"`
	EnabledEventTypes                   *[]string                               `json:"enabledEventTypes,omitempty"`
	EventsEnabled                       *bool                                   `json:"eventsEnabled,omitempty"`
	EventsExpiration                    *int64                                  `json:"eventsExpiration,omitempty"`
	EventsListeners                     *[]string                               `json:"eventsListeners,omitempty"`
	FailureFactor                       *int32                                  `json:"failureFactor,omitempty"`
	FederatedUsers                      *[]UserRepresentation                   `json:"federatedUsers,omitempty"`
	Groups                              *[]GroupRepresentation                  `json:"groups,omitempty"`
	Id                                  *string                                 `json:"id,omitempty"`
	IdentityProviderMappers             *[]IdentityProviderMapperRepresentation `json:"identityProviderMappers,omitempty"`
	IdentityProviders                   *[]IdentityProviderRepresentation       `json:"identityProviders,omitempty"`
	InternationalizationEnabled         *bool                                   `json:"internationalizationEnabled,omitempty"`
	KeycloakVersion                     *string                                 `json:"keycloakVersion,omitempty"`
	LoginTheme                          *string                                 `json:"loginTheme,omitempty"`
	LoginWithEmailAllowed               *bool                                   `json:"loginWithEmailAllowed,omitempty"`
	MaxDeltaTimeSeconds                 *int32                                  `json:"maxDeltaTimeSeconds,omitempty"`
	MaxFailureWaitSeconds               *int32                                  `json:"maxFailureWaitSeconds,omitempty"`
	MinimumQuickLoginWaitSeconds        *int32                                  `json:"minimumQuickLoginWaitSeconds,omitempty"`
	NotBefore                           *int32                                  `json:"notBefore,omitempty"`
	OfflineSessionIdleTimeout           *int32                                  `json:"offlineSessionIdleTimeout,omitempty"`
	OtpPolicyAlgorithm                  *string                                 `json:"otpPolicyAlgorithm,omitempty"`
	OtpPolicyDigits                     *int32                                  `json:"otpPolicyDigits,omitempty"`
	OtpPolicyInitialCounter             *int32                                  `json:"otpPolicyInitialCounter,omitempty"`
	OtpPolicyLookAheadWindow            *int32                                  `json:"otpPolicyLookAheadWindow,omitempty"`
	OtpPolicyPeriod                     *int32                                  `json:"otpPolicyPeriod,omitempty"`
	OtpPolicyType                       *string                                 `json:"otpPolicyType,omitempty"`
	OtpSupportedApplications            *[]string                               `json:"otpSupportedApplications,omitempty"`
	PasswordPolicy                      *string                                 `json:"passwordPolicy,omitempty"`
	PermanentLockout                    *bool                                   `json:"permanentLockout,omitempty"`
	ProtocolMappers                     *[]ProtocolMapperRepresentation         `json:"protocolMappers,omitempty"`
	QuickLoginCheckMilliSeconds         *int64                                  `json:"quickLoginCheckMilliSeconds,omitempty"`
	Realm                               *string                                 `json:"realm,omitempty"`
	RefreshTokenMaxReuse                *int32                                  `json:"refreshTokenMaxReuse,omitempty"`
	RegistrationAllowed                 *bool                                   `json:"registrationAllowed,omitempty"`
	RegistrationEmailAsUsername         *bool                                   `json:"registrationEmailAsUsername,omitempty"`
	RegistrationFlow                    *string                                 `json:"registrationFlow,omitempty"`
	RememberMe                          *bool                                   `json:"rememberMe,omitempty"`
	RequiredActions                     *[]RequiredActionProviderRepresentation `json:"requiredActions,omitempty"`
	ResetCredentialsFlow                *string                                 `json:"resetCredentialsFlow,omitempty"`
	ResetPasswordAllowed                *bool                                   `json:"resetPasswordAllowed,omitempty"`
	RevokeRefreshToken                  *bool                                   `json:"revokeRefreshToken,omitempty"`
	Roles                               *RolesRepresentation                    `json:"roles,omitempty"`
	ScopeMappings                       *[]ScopeMappingRepresentation           `json:"scopeMappings,omitempty"`
	SmtpServer                          *map[string]interface{}                 `json:"smtpServer,omitempty"`
	SslRequired                         *string                                 `json:"sslRequired,omitempty"`
	SSOSessionIdleTimeout               *int32                                  `json:"ssoSessionIdleTimeout,omitempty"`
	SSOSessionMaxLifespan               *int32                                  `json:"ssoSessionMaxLifespan,omitempty"`
	SupportedLocales                    *[]string                               `json:"supportedLocales,omitempty"`
	Users                               *[]UserRepresentation                   `json:"users,omitempty"`
	VerifyEmail                         *bool                                   `json:"verifyEmail,omitempty"`
	WaitIncrementSeconds                *int32                                  `json:"waitIncrementSeconds,omitempty"`
}
type ClientCreateRequest struct {
	Attributes   *map[string]interface{} `json:"attributes,omitempty"`
	ClientID     *string                 `json:"clientId,omitempty"`
	Enabled      *bool                   `json:"enabled,omitempty"`
	Protocol     *string                 `json:"protocol,omitempty"`
	RedirectURIs *[]string               `json:"redirectUris,omitempty"`
}

type MappingsRepresentation struct {
	ClientMappings *map[string]interface{} `json:"clientMappings,omitempty"`
	RealmMappings  *[]RoleRepresentation   `json:"realmMappings,omitempty"`
}

// HTTPError is returned when an error occurred while contacting the keycloak instance.
type HTTPError struct {
	HTTPStatus int
	Message    string
}

func (e HTTPError) Error() string {
	return e.Message
}

type Token struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
	Username       string `json:"preferred_username,omitempty"`
}

type header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}

type UserDetailsRepresentation struct {
	ID             *string                 `json:"id,omitempty"`
	Username       *string                 `json:"username,omitempty"`
	FirstName      *string                 `json:"firstName,omitempty"`
	LastName       *string                 `json:"lastName,omitempty"`
	Email          *string                 `json:"email,omitempty"`
	Enabled        *bool                   `json:"enabled,omitempty"`
	FederationLink *string                 `json:"federationLink,omitempty"`
	Roles          *MappingsRepresentation `json:"roles,omitempty"`
	Groups         *[]GroupRepresentation  `json:"groups,omitempty"`
	Attributes     *map[string][]string    `json:"attributes,omitempty"`
}

type Users []UserRepresentation

// ClientScopeRepresentation wraps keycloak client scope data
type ClientScopeRepresentation struct {
	Id              *string                         `json:"id,omitempty"`
	Name            *string                         `json:"name,omitempty"`
	Description     *string                         `json:"description,omitempty"`
	Protocol        *string                         `json:"protocol,omitempty"`
	ProtocolMappers *[]ProtocolMapperRepresentation `json:"protocolMappers,omitempty"`
	Attributes      *map[string][]string            `json:"attributes,omitempty"`
}

type UserFederationProviderRepresentation struct {
	Id          *string `json:"id,omitempty"`
	DisplayName *string `json:"name,omitempty"`
	// The id of the resource the provider is attached to
	// will be realm id for a user federation provider or
	// provider id for a user federation provider mapper
	ParentId *string `json:"parentId,omitempty"`
	// User viewable type of the provider
	ProviderId *string `json:"providerId,omitempty"`
	// Keycloak defined type corresponding to the ProviderId
	ProviderType *string              `json:"providerType,omitempty"`
	Config       *map[string][]string `json:"config,omitempty"`
}

type UserFederationProviderMapperRepresentation = UserFederationProviderRepresentation

type AuthenticationExecutionInfoRepresentation struct {
	Alias                *string   `json:"alias,omitempty"`
	AuthenticationConfig *string   `json:"authenticationConfig,omitempty"`
	AuthenticationFlow   *bool     `json:"authenticationFlow,omitempty"`
	Configurable         *bool     `json:"configurable,omitempty"`
	DisplayName          *string   `json:"displayName,omitempty"`
	FlowId               *string   `json:"flowId,omitempty"`
	Id                   *string   `json:"id,omitempty"`
	Index                *int32    `json:"index,omitempty"`
	Level                *int32    `json:"level,omitempty"`
	ProviderId           *string   `json:"providerId,omitempty"`
	Requirement          *string   `json:"requirement,omitempty"`
	RequirementChoices   *[]string `json:"requirementChoices,omitempty"`
}

type InitiatePKCELogin struct {
	Nonce               string `schema:"nonce"`
	ClientID            string `schema:"client_id"`
	ResponseType        string `schema:"response_type"`
	Scope               string `schema:"scope"`
	RedirectURI         string `schema:"redirect_uri"`
	ResponseMode        string `schema:"response_mode"`
	State               string `schema:"state"`
	Username            string `schema:"username"`
	Target              string `schema:"target"`
	AuthSessionID       string `schema:"auth_session_id"`
	CodeChallenge       string `schema:"code_challenge"`
	CodeChallengeMethod string `schema:"code_challenge_method"`
}
