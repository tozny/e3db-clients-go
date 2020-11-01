package identityClient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/utils-go/server"
)

const (
	identityServiceBasePath       = "/v1/identity" // HTTP PATH prefix for calls to the Identity service
	realmResourceName             = "realm"
	providerResourceName          = "provider"
	providerMapperResourceName    = "mapper"
	applicationResourceName       = "application"
	identityResourceName          = "identity"
	roleResourceName              = "role"
	groupResourceName             = "group"
	roleMapperResourceName        = "role_mapping"
	realmLoginPathPrefix          = "/auth/realms"
	realmLoginPathPostfix         = "/protocol/openid-connect/token"
	applicationMapperResourceName = "mapper"
)

var (
	internalIdentityServiceBasePath = fmt.Sprintf("/internal%s", identityServiceBasePath)
)

// E3dbIdentityClient implements an http client for communication with an e3db Identity service.
type E3dbIdentityClient struct {
	Host        string
	SigningKeys e3dbClients.SigningKeys
	ClientID    string
	httpClient  *http.Client
}

// ListRealmApplicationMappers lists the applicationMappers for a given realm or error (if any).
func (c *E3dbIdentityClient) ListRealmApplicationMappers(ctx context.Context, params ListRealmApplicationMappersRequest) (*ListRealmApplicationMappersResponse, error) {
	var applicationMappers *ListRealmApplicationMappersResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + applicationMapperResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return applicationMappers, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationMappers)
	return applicationMappers, err
}

// DeleteRealmApplicationMapper deletes the specified realm application mapper, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmApplicationMapper(ctx context.Context, params DeleteRealmApplicationMapperRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + applicationMapperResourceName + "/" + params.ApplicationMapperID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmApplicationMapper describes the realm application mapper with the specified id, returning the application mapper or error (if any).
func (c *E3dbIdentityClient) DescribeRealmApplicationMapper(ctx context.Context, params DescribeRealmApplicationMapperRequest) (*ApplicationMapper, error) {
	var applicationMapper *ApplicationMapper
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + applicationMapperResourceName + "/" + params.ApplicationMapperID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return applicationMapper, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationMapper)
	return applicationMapper, err
}

// CreateRealmApplicationMapper creates a realm application mapper using the specified parameters,
// returning the created realm application mapper or error (if any).
func (c *E3dbIdentityClient) CreateRealmApplicationMapper(ctx context.Context, params CreateRealmApplicationMapperRequest) (*ApplicationMapper, error) {
	var applicationMapper *ApplicationMapper
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + applicationMapperResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.ApplicationMapper)
	if err != nil {
		return applicationMapper, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationMapper)
	return applicationMapper, err
}

// FetchApplicationSecret retrieves the secret (if any) for the application or error (if any).
func (c *E3dbIdentityClient) FetchApplicationSecret(ctx context.Context, params FetchApplicationSecretRequest) (*ApplicationSecret, error) {
	var secret *ApplicationSecret
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/secret"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return secret, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &secret)
	return secret, err
}

// FetchApplicationSAMLDescription retrieves the SAML description (if any) for the application in the specified format or error (if any).
func (c *E3dbIdentityClient) FetchApplicationSAMLDescription(ctx context.Context, params FetchApplicationSAMLDescriptionRequest) (*ApplicationSAMLDescription, error) {
	var description *ApplicationSAMLDescription
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/installation/providers/" + params.Format
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return description, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &description)
	return description, err
}

// ListRealmRoles lists the roles for a given realm or error (if any).
func (c *E3dbIdentityClient) ListRealmRoles(ctx context.Context, realmName string) (*ListRealmRolesResponse, error) {
	var roles *ListRealmRolesResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + realmName + "/" + roleResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return roles, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &roles)
	return roles, err
}

// DeleteRealmRole deletes the specified realm role, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmRole(ctx context.Context, params DeleteRealmRoleRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + roleResourceName + "/" + params.RoleID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmRole describes the realm role with the specified id, returning the role or error (if any).
func (c *E3dbIdentityClient) DescribeRealmRole(ctx context.Context, params DescribeRealmRoleRequest) (*Role, error) {
	var role *Role
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + roleResourceName + "/" + params.RoleID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return role, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &role)
	return role, err
}

// CreateRealmRole creates a realm role using the specified parameters,
// returning the created realm role or error (if any).
func (c *E3dbIdentityClient) CreateRealmRole(ctx context.Context, params CreateRealmRoleRequest) (*Role, error) {
	var role *Role
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + roleResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.Role)
	if err != nil {
		return role, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &role)
	return role, err
}

// ListGroupRoleMappings lists all the realm and application role mappings for a group or error (if any).
func (c *E3dbIdentityClient) ListGroupRoleMappings(ctx context.Context, params ListGroupRoleMappingsRequest) (*RoleMapping, error) {
	var roleMappings *RoleMapping
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName + "/" + params.GroupID + "/" + roleMapperResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return roleMappings, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &roleMappings)
	return roleMappings, err
}

// RemoveGroupRoleMappings removes the specified role mappings from a group
// returning nil on success or error (if any).
func (c *E3dbIdentityClient) RemoveGroupRoleMappings(ctx context.Context, params RemoveGroupRoleMappingsRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName + "/" + params.GroupID + "/" + roleMapperResourceName
	request, err := e3dbClients.CreateRequest("DELETE", path, params.RoleMapping)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// AddGroupRoleMappings adds the specified role mappings to the group
// returning nil on success or error (if any).
func (c *E3dbIdentityClient) AddGroupRoleMappings(ctx context.Context, params AddGroupRoleMappingsRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName + "/" + params.GroupID + "/" + roleMapperResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.RoleMapping)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// ListIdentities in a given realm in a paginated way.
func (c *E3dbIdentityClient) ListIdentities(ctx context.Context, params ListIdentitiesRequest) (*ListIdentitiesResponse, error) {
	var identities *ListIdentitiesResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + identityResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return identities, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("first", strconv.Itoa(int(params.First)))
	urlParams.Set("max", strconv.Itoa(int(params.Max)))
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identities)
	return identities, err
}

// DescribeIdentity gets detailed information for an identity in a given realm.
func (c *E3dbIdentityClient) DescribeIdentity(ctx context.Context, realmName string, clientID string) (*IdentityDetails, error) {
	var identity *IdentityDetails
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + realmName + "/" + identityResourceName + "/" + clientID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identity)
	return identity, err
}

// ListRealmProviderMappers lists the mappers for a given realm provider or error (if any).
func (c *E3dbIdentityClient) ListRealmProviderMappers(ctx context.Context, params ListRealmProviderMappersRequest) (*ListRealmProviderMappersResponse, error) {
	var providerMappers *ListRealmProviderMappersResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID + "/" + providerMapperResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return providerMappers, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &providerMappers)
	return providerMappers, err
}

// DeleteRealmProviderMapper deletes the specified realm provider mapper, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmProviderMapper(ctx context.Context, params DeleteRealmProviderMapperRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID + "/" + providerMapperResourceName + "/" + params.ProviderMapperID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmProviderMapper describes the realm provider mapper with the specified id, returning the provider mapper or error (if any).
func (c *E3dbIdentityClient) DescribeRealmProviderMapper(ctx context.Context, params DescribeRealmProviderMapperRequest) (*ProviderMapper, error) {
	var providerMapper *ProviderMapper
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID + "/" + providerMapperResourceName + "/" + params.ProviderMapperID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return providerMapper, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &providerMapper)
	return providerMapper, err
}

// CreateRealmProviderMapper creates a realm provider mapper using the specified parameters,
// returning the created realm provider mapper or error (if any).
func (c *E3dbIdentityClient) CreateRealmProviderMapper(ctx context.Context, params CreateRealmProviderMapperRequest) (*ProviderMapper, error) {
	var providerMapper *ProviderMapper
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID + "/" + providerMapperResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.ProviderMapper)
	if err != nil {
		return providerMapper, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &providerMapper)
	return providerMapper, err
}

// ListRealmProviders lists the providers for a given realm or error (if any).
func (c *E3dbIdentityClient) ListRealmProviders(ctx context.Context, realmName string) (*ListRealmProvidersResponse, error) {
	var providers *ListRealmProvidersResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + realmName + "/" + providerResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return providers, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &providers)
	return providers, err
}

// DeleteRealmProvider deletes the specified realm provider, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmProvider(ctx context.Context, params DeleteRealmProviderRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmProvider describes the realm provider with the specified id, returning the provider or error (if any).
func (c *E3dbIdentityClient) DescribeRealmProvider(ctx context.Context, params DescribeRealmProviderRequest) (*Provider, error) {
	var provider *Provider
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName + "/" + params.ProviderID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return provider, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &provider)
	return provider, err
}

// CreateRealmProvider creates a realm provider using the specified parameters,
// returning the created realm provider or error (if any).
func (c *E3dbIdentityClient) CreateRealmProvider(ctx context.Context, params CreateRealmProviderRequest) (*Provider, error) {
	var provider *Provider
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + providerResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.Provider)
	if err != nil {
		return provider, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &provider)
	return provider, err
}

// ListRealmApplications lists the applications for a given realm or error (if any).
func (c *E3dbIdentityClient) ListRealmApplications(ctx context.Context, realmName string) (*ListRealmApplicationsResponse, error) {
	var applications *ListRealmApplicationsResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + realmName + "/" + applicationResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return applications, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applications)
	return applications, err
}

// DeleteRealmApplication deletes the specified realm application, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmApplication(ctx context.Context, params DeleteRealmApplicationRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmApplication describes the realm application with the specified id, returning the application or error (if any).
func (c *E3dbIdentityClient) DescribeRealmApplication(ctx context.Context, params DescribeRealmApplicationRequest) (*Application, error) {
	var application *Application
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return application, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &application)
	return application, err
}

// CreateRealmApplication creates a realm application using the specified parameters,
// returning the created realm application or error (if any).
func (c *E3dbIdentityClient) CreateRealmApplication(ctx context.Context, params CreateRealmApplicationRequest) (*Application, error) {
	var application *Application
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.Application)
	if err != nil {
		return application, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &application)
	return application, err
}

// ListRealmApplicationRoles lists the realm application roles of the specified realm, returning the application roles or error (if any).
func (c *E3dbIdentityClient) ListRealmApplicationRoles(ctx context.Context, params ListRealmApplicationRolesRequest) (*ListRealmApplicationRolesResponse, error) {
	var applicationRoles *ListRealmApplicationRolesResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + roleResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return applicationRoles, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationRoles)
	return applicationRoles, err
}

// DeleteRealmApplicationRole deletes the specified realm application role, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmApplicationRole(ctx context.Context, params DeleteRealmApplicationRoleRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + roleResourceName + "/" + url.QueryEscape(params.ApplicationRoleName)
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmApplicationRole describes the realm application role with the specified id, returning the application or error (if any).
func (c *E3dbIdentityClient) DescribeRealmApplicationRole(ctx context.Context, params DescribeRealmApplicationRoleRequest) (*ApplicationRole, error) {
	var applicationRole *ApplicationRole
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + roleResourceName + "/" + url.QueryEscape(params.ApplicationRoleName)
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return applicationRole, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationRole)
	return applicationRole, err
}

// CreateRealmApplicationRole creates a realm application role using the specified parameters,
// returning the created realm application role or error (if any).
func (c *E3dbIdentityClient) CreateRealmApplicationRole(ctx context.Context, params CreateRealmApplicationRoleRequest) (*ApplicationRole, error) {
	var applicationRole *ApplicationRole
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + applicationResourceName + "/" + params.ApplicationID + "/" + roleResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.ApplicationRole)
	if err != nil {
		return applicationRole, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &applicationRole)
	return applicationRole, err
}

// ListRealmGroups lists the realm application roles of the specified realm, returning the application roles or error (if any).
func (c *E3dbIdentityClient) ListRealmGroups(ctx context.Context, params ListRealmGroupsRequest) (*ListRealmGroupsResponse, error) {
	var groups *ListRealmGroupsResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return groups, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &groups)
	return groups, err
}

// DeleteRealmGroup deletes the specified realm group, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealmGroup(ctx context.Context, params DeleteRealmGroupRequest) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName + "/" + params.GroupID
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealmGroup describes the realm group with the specified id, returning the realm group or error (if any).
func (c *E3dbIdentityClient) DescribeRealmGroup(ctx context.Context, params DescribeRealmGroupRequest) (*Group, error) {
	var group *Group
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName + "/" + params.GroupID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return group, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &group)
	return group, err
}

// CreateRealmGroup creates a realm group using the specified parameters,
// returning the created realm group or error (if any).
func (c *E3dbIdentityClient) CreateRealmGroup(ctx context.Context, params CreateRealmGroupRequest) (*Group, error) {
	var group *Group
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + "/" + params.RealmName + "/" + groupResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params.Group)
	if err != nil {
		return group, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &group)
	return group, err
}

// ListOIDCKeysForRealm returns a list of all configured keys for OIDC flows for a given realm and error (if any)
func (c *E3dbIdentityClient) ListOIDCKeysForRealm(ctx context.Context, realmName string) (ListRealmOIDCKeysResponse, error) {
	var listedKeys ListRealmOIDCKeysResponse
	path := fmt.Sprintf("%s%s/%s/protocol/openid-connect/certs", c.Host, realmLoginPathPrefix, strings.ToLower(realmName))
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return listedKeys, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &listedKeys)
	if err != nil {
		return listedKeys, err
	}
	return listedKeys, err
}

// BrokerIdentityChallange begins a broker-based login flow using the specified params, returning error (if any).
func (c *E3dbIdentityClient) BrokerIdentityChallenge(ctx context.Context, params BrokerChallengeRequest) error {
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/broker/%s/%s/challenge", realmResourceName, params.RealmName)
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return err
	}
	return e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
}

// RegisterIdentity completes a broker based login flow by giving the broker the needed authentication
// information returning the recovery note and error (if any).
func (c *E3dbIdentityClient) BrokerIdentityLogin(ctx context.Context, params BrokerLoginRequest) (*BrokerLoginResponse, error) {
	var identity *BrokerLoginResponse
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/broker/%s/%s/login", realmResourceName, params.RealmName)
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

// RegisterRealmBrokerIdentity creates and associates an Identity to be used
// to backup the credentials for the realm's Identities, returning the created identity and error (if any).
func (c *E3dbIdentityClient) RegisterRealmBrokerIdentity(ctx context.Context, params RegisterRealmBrokerIdentityRequest) (*RegisterRealmBrokerIdentityResponse, error) {
	var identity *RegisterRealmBrokerIdentityResponse
	path := c.Host + identityServiceBasePath + fmt.Sprintf("/%s/%s/broker/identity", realmResourceName, strings.ToLower(params.RealmName))
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identity)
	return identity, err
}

// GetToznyHostedBrokerInfo returns info about the Tozny Hosted Broker,
// or error (if any).
func (c *E3dbIdentityClient) GetToznyHostedBrokerInfo(ctx context.Context) (*ToznyHostedBrokerInfoResponse, error) {
	var toznyHostedBrokerInfo *ToznyHostedBrokerInfoResponse
	path := c.Host + identityServiceBasePath + "/broker/info"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return toznyHostedBrokerInfo, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &toznyHostedBrokerInfo)
	return toznyHostedBrokerInfo, err
}

// IdentityLogin logs in the client identity to the specified realm,
// returning the identities realm authentication info and error (if any).
func (c *E3dbIdentityClient) IdentityLogin(ctx context.Context, realmName string) (*IdentityLoginResponse, error) {
	var identity *IdentityLoginResponse
	path := c.Host + realmLoginPathPrefix + fmt.Sprintf("/%s", strings.ToLower(realmName)) + realmLoginPathPostfix
	data := url.Values{}
	// All login requests are authenticated as valid tsv1 signed requests,
	// set these for compatibility with default Keycloak Oauth direct grant request handling.
	data.Set("grant_type", "password")
	// Not the actual realm admin, just an identity with API level access.
	data.Set("client_id", "admin-cli")
	request, err := http.NewRequest("POST", path, strings.NewReader(data.Encode()))
	if err != nil {
		return identity, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &identity)
	return identity, err
}

// InternalIdentityLogin requests internal authentication context
// for the ability of the authenticated identity to login into the specified realm
// returning the identities internal realm authentication context and error (if any).
func (c *E3dbIdentityClient) InternalIdentityLogin(ctx context.Context, params InternalIdentityLoginRequest) (*InternalIdentityLoginResponse, error) {
	var identity *InternalIdentityLoginResponse
	path := c.Host + internalIdentityServiceBasePath + fmt.Sprintf("/%s/%s", realmResourceName, params.RealmName) + "/login"
	request, err := e3dbClients.CreateRequest("POST", path, nil)
	if err != nil {
		return identity, err
	}
	request.Header.Set(server.ToznyAuthNHeader, params.XToznyAuthNHeader)
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

func (c *E3dbIdentityClient) InternalUpdateIdentityActiveByKeycloakUserID(ctx context.Context, keyCloakUserID string, active bool) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/user/" + keyCloakUserID + "/active"
	body := InternalUpdateActiveForKeycloakUserID{
		Active: active,
	}
	request, err := e3dbClients.CreateRequest("PUT", path, &body)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

func (c *E3dbIdentityClient) InternalDeleteIdentity(ctx context.Context, realmName string, keycloakUserID string, username string) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/user/" + realmName + "/" + keycloakUserID + "?username=" + username
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

func (c *E3dbIdentityClient) InternalDeleteIdentitiesByProvider(ctx context.Context, params InternalDeleteIdentitiesByProviderRequest) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/" + params.RealmName + "/id-provider/" + params.ProviderID.String()
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

// InternalSetLDAPCache stores LDAP information for a specific user by ID in a specific realm
func (c *E3dbIdentityClient) InternalSetLDAPCache(ctx context.Context, realmName string, params LDAPCache) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/" + realmName + "/ldap-cache"
	request, err := e3dbClients.CreateRequest(http.MethodPost, path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

// InternalLDAPCache gets LDAP information for a specific user by ID in a specific realm
func (c *E3dbIdentityClient) InternalLDAPCache(ctx context.Context, realmName string, keycloakUserID string) (LDAPCache, error) {
	var response LDAPCache
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/" + realmName + "/ldap-cache/" + keycloakUserID
	request, err := e3dbClients.CreateRequest(http.MethodGet, path, nil)
	if err != nil {
		return response, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &response)
	return response, err
}

// InternalDeleteLDAPCache removes LDAP information for a specific user by ID in a specific realm
func (c *E3dbIdentityClient) InternalDeleteLDAPCache(ctx context.Context, realmName string, keycloakUserID string) error {
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/" + realmName + "/ldap-cache/" + keycloakUserID
	request, err := e3dbClients.CreateRequest(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
	return err
}

// RegisterIdentity registers an identity with the specified realm using the specified parameters,
// returning the created identity and error (if any).
func (c *E3dbIdentityClient) RegisterIdentity(ctx context.Context, params RegisterIdentityRequest) (*RegisterIdentityResponse, error) {
	var identity *RegisterIdentityResponse
	path := c.Host + identityServiceBasePath + "/register"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return identity, err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, &identity)
	return identity, err
}

// ListRealms lists the realms belonging to the requester returning the realms and error (if any).
func (c *E3dbIdentityClient) ListRealms(ctx context.Context) (*ListRealmsResponse, error) {
	var realms *ListRealmsResponse
	path := c.Host + identityServiceBasePath + "/" + realmResourceName
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return realms, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realms)
	return realms, err
}

// DeleteRealm deletes the realm with the specified name, returning error (if any).
func (c *E3dbIdentityClient) DeleteRealm(ctx context.Context, realmName string) error {
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + fmt.Sprintf("/%s", realmName)
	request, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	return e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, nil)
}

// DescribeRealm describes the realm with the specified name, returning the realm and error (if any).
func (c *E3dbIdentityClient) DescribeRealm(ctx context.Context, realmName string) (*Realm, error) {
	var realm *Realm
	path := c.Host + identityServiceBasePath + "/" + realmResourceName + fmt.Sprintf("/%s", realmName)
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return realm, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realm)
	return realm, err
}

// CreateRealm creates a realm using the specified parameters,
// returning the created realm (including it's associated sovereign) and error (if any).
func (c *E3dbIdentityClient) CreateRealm(ctx context.Context, params CreateRealmRequest) (*Realm, error) {
	var realm *Realm
	path := c.Host + identityServiceBasePath + "/" + realmResourceName
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return realm, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &realm)
	return realm, err
}

func (c *E3dbIdentityClient) ChallengePushRequest(ctx context.Context, params UserChallengePushRequest) (InitiateUserChallengeResponse, error) {
	var resp InitiateUserChallengeResponse
	path := c.Host + internalIdentityServiceBasePath + "/keycloak/" + params.Realm + "/challenge/" + params.Username
	request, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return resp, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &resp)
	return resp, err
}

func (c *E3dbIdentityClient) CompleteChallengeRequest(ctx context.Context, params CompleteChallengeRequest) error {
	path := c.Host + identityServiceBasePath + "/challenge"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return err
	}
	client := &http.Client{}
	err = e3dbClients.MakeRawServiceCall(client, request, nil)
	return err
}

func (c *E3dbIdentityClient) InitiateRegisterUserDeviceRequest(ctx context.Context, params InitiateRegisterDeviceRequest) (InitiateRegisterDeviceResponse, error) {
	var resp InitiateRegisterDeviceResponse
	path := c.Host + identityServiceBasePath + "/register/device"
	request, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return resp, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, request, c.SigningKeys, c.ClientID, &resp)
	return resp, err
}

func (c *E3dbIdentityClient) CompleteRegisterUserDeviceRequest(ctx context.Context, params CompleteUserDeviceRegisterRequest) error {
	path := c.Host + identityServiceBasePath + "/register/device"
	request, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return err
	}
	client := &http.Client{}
	err = e3dbClients.MakeRawServiceCall(client, request, nil)
	return err
}

func (c *E3dbIdentityClient) IsChallengeCompleteRequest(ctx context.Context, challengeID string) error {
	path := c.Host + identityServiceBasePath + "/challenge/" + challengeID
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	client := &http.Client{}
	err = e3dbClients.MakeRawServiceCall(client, request, nil)
	return err
}

// ServiceCheck checks whether the identity service is up and working.
// returning error if unable to connect service
func (c *E3dbIdentityClient) ServiceCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/servicecheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
	return err
}

// HealthCheck checks whether the identity service is up,
// returning error if unable to connect to the service.
func (c *E3dbIdentityClient) HealthCheck(ctx context.Context) error {
	path := c.Host + identityServiceBasePath + "/healthcheck"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeRawServiceCall(c.httpClient, request, nil)
	return err
}

// New returns a new E3dbHookClient configured with the provided values
func New(config e3dbClients.ClientConfig) E3dbIdentityClient {
	return E3dbIdentityClient{
		Host:        config.Host,
		SigningKeys: config.SigningKeys,
		ClientID:    config.ClientID,
		httpClient:  &http.Client{},
	}
}
