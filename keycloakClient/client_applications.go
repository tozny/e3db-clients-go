package keycloakClient

import (
	"fmt"
	"net/http"
)

// GetClients returns a list of clients belonging to the realm.
// Parameters: clientId (filter by clientId),
// viewableOnly (filter clients that cannot be viewed in full by admin, default="false")
func (c *Client) GetClients(accessToken string, realmName string, paramKV ...string) ([]ClientRepresentation, error) {
	var err error
	var resp = []ClientRepresentation{}
	if len(paramKV)%2 != 0 {
		return nil, fmt.Errorf("the number of key/val parameters should be even")
	}
	url := fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, clientResourceName)
	path := c.apiURL.String() + url

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return resp, err
	}
	if len(paramKV) > 0 {
		urlParams := req.URL.Query()
		// Sketchy
		for i := 0; i < len(paramKV)/2; i += 2 {
			urlParams.Set(paramKV[i], paramKV[i+1])
		}
		req.URL.RawQuery = urlParams.Encode()
	}
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// GetClientRoles gets all roles for the realm or client
func (c *Client) GetClientRoles(accessToken string, realmName string, clientID string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName))
	return resp, err
}

// CreateClientRole creates a new role for the realm or client
func (c *Client) CreateClientRole(accessToken string, realmName string, clientID string, role RoleRepresentation) (string, error) {
	return c.post(accessToken, role, fmt.Sprintf("%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName))
}

// DeleteRole deletes a role
func (c *Client) DeleteRole(accessToken string, realmName string, clientID string, roleID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName, roleID))
}

// GetClientRole gets a specific client role’s representation
func (c *Client) GetClientRole(accessToken string, realmName string, clientID string, roleID string) (RoleRepresentation, error) {
	var resp = RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, roleResourceName, roleID))
	return resp, err
}

// UpdateClientRoleByID updates a specific client role’s representation
func (c *Client) UpdateClientRoleByID(accessToken string, realmName string, roleId string, role RoleRepresentation) error {
	return c.put(accessToken, role, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, roleByIDResourceName, roleId))
}

// GetClientRoleMappings gets client-level role mappings for the user, and the app.
func (c *Client) GetClientRoleMappings(accessToken string, realmName, userID, clientID string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, clientResourceName, clientID))
	return resp, err
}

// AddClientRoleMapping add client-level roles to the user role mapping.
func (c *Client) AddClientRolesToUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []RoleRepresentation) error {
	_, err := c.post(accessToken, roles, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, clientResourceName, clientID))
	return err
}

// RemoveClientRolesFromUserRoleMapping removes client-level roles from a user role mapping
// returning error (if any).
func (c *Client) RemoveClientRolesFromUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []RoleRepresentation) error {
	err := c.delete(accessToken, roles, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, userResourceName, userID, roleMappingResourceName, clientResourceName, clientID))
	return err
}

// Access Control Policy Endpoints
// ==========================================================================
// Disable Access Policy Endpoints
// ==========================================================================

// RemoveResourceServerResource deletes a resource from the resource server for the client
func (c *Client) RemoveResourceServerResource(accessToken string, realmName string, clientID string, resourceID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, resourceResourceName, resourceID))
}

// RemoveResourceServerPolicy deletes a policy from the resource server for the client
func (c *Client) RemoveResourceServerPolicy(accessToken string, realmName string, clientID string, policyID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName, policyID))
}

// ==========================================================================
// Enable Access Policy Endpoints
// ==========================================================================

// CreateResourceServerResource
func (c *Client) CreateResourceServerResource(accessToken string, realmName string, clientID string, request CreatePermissionRequest) (string, error) {
	return c.post(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, resourceResourceName))
}

// CreateResourceServerStaticPolicy
func (c *Client) CreateResourceServerStaticPolicy(accessToken string, realmName string, clientID string, request CreatePolicyRequest) (string, error) {
	return c.post(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName, staticResourceName))
}

// CreateResourceServerResourcePermission
func (c *Client) CreateResourceServerResourcePermission(accessToken string, realmName string, clientID string, request CreateResourceRequest) (string, error) {
	return c.post(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, permissionResourceName, resourceResourceName))
}

// ==========================================================================
// Create and Update Access Control Policy
// ==========================================================================

// CreateResourceServerGroupPolicy
func (c *Client) CreateResourceServerGroupPolicy(accessToken string, realmName string, clientID string, request CreateGroupPolicyRequest) (string, error) {
	return c.post(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName, groupResourceName))
}

// UpdateResourceServerGroupPermission
func (c *Client) UpdateResourceServerGroupPermission(accessToken string, realmName string, clientID string, policyID string, request UpdateAccessControlPolicy) error {
	return c.put(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, permissionResourceName, resourceResourceName, policyID))
}

// UpdateResourceServerGroupsPolicy
func (c *Client) UpdateResourceServerGroupsPolicy(accessToken string, realmName string, clientID string, groupPolicyID string, request UpdateAccessControlGroupPolicy) error {
	return c.put(accessToken, request, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName, groupResourceName, groupPolicyID))
}

// ==========================================================================
// Remove Group Access Control Policy
// ==========================================================================

// RemoveGroupResourceServerPolicy deletes a group policy from the resource server for the client
func (c *Client) RemoveGroupResourceServerPolicy(accessToken string, realmName string, clientID string, policyID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName, policyID))
}

// ==========================================================================

// GetSAMLDescription gets the saml description for a client. idClient is the id of client (not client-id).
// GET https://id.tozny.com/auth/admin/realms/demorealm/clients/13be9337-b349-4e1a-9b1a-32fd227e0d0f/installation/providers/saml-idp-descriptor
// <?xml version="1.0" encoding="UTF-8"?>
// <EntityDescriptor entityID="https://id.tozny.com/auth/realms/demorealm"
//                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
//                    xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
//                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
//    <IDPSSODescriptor WantAuthnRequestsSigned="false"
//       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
//       <SingleLogoutService
//          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <SingleLogoutService
//          Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
//    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
//       <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
//          Location="https://id.tozny.com/auth/realms/demorealm/protocol/saml" />
//       <KeyDescriptor use="signing">
//         <dsig:KeyInfo>
//           <dsig:KeyName>xKHm8qTWp9Dppc6jOtcKkN8thWLSJ8OVHeVND7rH-1s</dsig:KeyName>
//           <dsig:X509Data>
//             <dsig:X509Certificate>MIICoTCCAYkCBgF1BX2OcTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlkZW1vcmVhbG0wHhcNMjAxMDA3MjM1MzM1WhcNMzAxMDA3MjM1NTE1WjAUMRIwEAYDVQQDDAlkZW1vcmVhbG0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnwsBYFAnxrr36yjXen3+2LxuDqeBl7+qy+qkAOD91Pe7gokeY9aXkyQedb4kII37i6iPAwtCHg/PjwU3unufqB8hGmy/GTdq95u8DOrKcFDutNG8P/51qxGTDZVni5NzO6kchXSK/RHJgi47vbmPN7MzLZopuw2q1ulXmPkRYEGNALuW3Ofv8AwdvADRj7+Fq7VpIZmHsgMS+ujnnMYtISqENDP5qXAm+k2Ux69rgba5hNcFwwu9sipD+Ybc6MxtQxcKJh9ciPLoq+HYFpoF5uiBSzbgCZ7mrK/7/dZrrYC73+65ZGt6f0VHWMVjwpKUkqlCYOxGqRx7lrpZ967wfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABTSiOQ+Gi5Qer3nf7xoXbYuzv5/RwcilWOrnEmqLiM84nkH1nAiF0axDBFUv5NpqqEEb2VyyZz+pIfLiEhPwjpy03t24XLAz+S9CsQW7LNtfVobrf52dzofe/5NHymq2WtnBeOtt7HSgHVPUmTzBbA3HDKP5N4p359j32ElxcgSZOmC2IFNDcoVC39pylmTHuZ6MGOD6skeIANXxtU77HKPATLl9AkxOz7k5y+AiBJjsTmYxZVhhr72+8jyumeWq30K8SeO5CryU+JFvz5rljacZspGEgWoqaiqXxtENs9+K29lB1EB9delhSJkZ+u7gxQwkSTVYhkS6FZQfH2tuTE=</dsig:X509Certificate>
//           </dsig:X509Data>
//         </dsig:KeyInfo>
//       </KeyDescriptor>
//    </IDPSSODescriptor>
// </EntityDescriptor>
func (c *Client) GetSAMLDescription(accessToken string, realmName string, idClient string, format string) (string, error) {
	var description string
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/clients/" + idClient + "/installation/providers/" + format
	request, err := createVanillaRequest("GET", path, nil)
	if err != nil {
		return description, err
	}
	description, err = makePlainTextCall(accessToken, request)
	return description, err
}

// GetClient get the representation of the client. idClient is the id of client (not client-id).
func (c *Client) GetClient(accessToken string, realmName string, idClient string) (ClientRepresentation, error) {
	var response = ClientRepresentation{}
	var err = c.get(accessToken, &response, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, idClient))
	return response, err
}

// UpdateClient updates the client.
func (c *Client) UpdateClient(accessToken string, realmName string, clientID string, client ClientRepresentation) error {
	return c.put(accessToken, client, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID))
}

// DeleteClient deletes specified client from the realm. id is the id of client (not client-id).
func (c *Client) DeleteClient(accessToken string, realmName string, clientID string) error {
	return c.delete(accessToken, nil, fmt.Sprintf("%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID))
}

// CreateClient creates a client
func (c *Client) CreateClient(accessToken string, realmName string, client ClientCreateRequest) (string, error) {
	return c.post(accessToken, client, fmt.Sprintf("%s/%s/%s", realmRootPath, realmName, clientResourceName))
}

// GetGroupClientRoleMappings returns the assigned client roles for a group and error (if any).
// >	GET http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) GetGroupClientRoleMappings(accessToken, realmName, groupId, clientId string) ([]RoleRepresentation, error) {
	var resp = []RoleRepresentation{}
	var err = c.get(accessToken, &resp, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, clientResourceName, clientId))
	return resp, err
}

// AddGroupClientRoleMappings adds client role mappings for a group, returning error (if any)
// >	POST http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) AddGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	_, err := c.post(accessToken, roleMappings, fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, groupResourceName, groupId, roleMappingResourceName, clientResourceName, clientId))
	return err
}

// RemoveGroupClientRoleMappings removes client role mapping(s) from a group, returning error (if any)
// >	DELETE http://localhost:8000/auth/admin/realms/demo/groups/80206962-5dcb-4252-8cbb-2e828c1d010b/role-mappings/clients/a3bdb226-f718-4c69-9f59-76df1dda1362
// ```json
// [
//   {
//     "id": "945ae18b-5cd5-48c5-9fa8-e5b43555d71f",
//     "name": "Admin",
//     "description": "Allow all.",
//     "composite": false,
//     "clientRole": true,
//     "containerId": "a3bdb226-f718-4c69-9f59-76df1dda1362"
//   }
// ]
func (c *Client) RemoveGroupClientRoleMappings(accessToken, realmName, groupId, clientId string, roleMappings []RoleRepresentation) error {
	path := c.apiURL.String() + "/auth/admin/realms/" + realmName + "/groups/" + groupId + "/role-mappings/clients/" + clientId
	request, err := createVanillaRequest("DELETE", path, roleMappings)
	if err != nil {
		return err
	}
	return makeJSONCall(accessToken, request, nil)
}

// GetToznyInternalGroupPolicy
func (c *Client) GetToznyInternalGroupPolicy(accessToken string, realmName string, clientID string) ([]InternalGroupPolicy, error) {
	resp := []InternalGroupPolicy{}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName)
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)
	urlParams := req.URL.Query()
	urlParams.Set("name", toznyInternalGroupPolicyName)
	req.URL.RawQuery = urlParams.Encode()
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// GetToznyInternalDenyPolicy
func (c *Client) GetToznyInternalDenyPolicy(accessToken string, realmName string, clientID string) ([]InternalDenyPolicy, error) {
	resp := []InternalDenyPolicy{}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, policyResourceName)
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)
	urlParams := req.URL.Query()
	urlParams.Set("name", toznyInternalDenyPolicyName)
	req.URL.RawQuery = urlParams.Encode()
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// GetToznyInternalAuthorizationPermission
func (c *Client) GetToznyInternalAuthorizationPermission(accessToken string, realmName string, clientID string) ([]InternalAuthorizationPermission, error) {
	resp := []InternalAuthorizationPermission{}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, permissionResourceName)
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)
	urlParams := req.URL.Query()
	urlParams.Set("name", toznyInternalAuthzMap)
	req.URL.RawQuery = urlParams.Encode()
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}

// GetToznyInternalAuthorizationResource
func (c *Client) GetToznyInternalAuthorizationResource(accessToken string, realmName string, clientID string) ([]InternalAuthorizationResource, error) {
	resp := []InternalAuthorizationResource{}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", realmRootPath, realmName, clientResourceName, clientID, authzResourceName, resourceServerResourceName, resourceResourceName)
	path := c.apiURL.String() + url
	req, err := http.NewRequest("GET", path, nil)
	urlParams := req.URL.Query()
	urlParams.Set("name", toznyInternalAuthzMap)
	req.URL.RawQuery = urlParams.Encode()
	err = c.requestWithQueryParams(accessToken, req, &resp)
	return resp, err
}
