package identityClient

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/test"
)

// VerifyIncludeDetailsForDetailedIdentity checks that a DetailedFederatedIdentity has additional details after a
// sync that set the IncludeDetails filter
func VerifyIncludeDetailsForDetailedIdentity(federatedIdentities []DetailedFederatedIdentity) error {
	var err error
	for _, identity := range federatedIdentities {
		if identity.Active == false {
			err = errors.New("expected DetailedFederatedIdentity to be Active")
			break
		}
		if identity.Attributes == nil {
			err = errors.New("expected DetailedFederatedIdentity to have Attributes")
			break
		}
		if identity.Roles.ClientRoles == nil {
			err = errors.New("expected Client Roles for DetailedFederatedIdentity")
			break
		}
		if identity.Roles.RealmRoles == nil {
			err = errors.New("expected Realm Roles for DetailedFederatedIdentity")
			break
		}
		if identity.Group == nil {
			err = errors.New("expected non-nil Group infromation for DetailedFederatedIdentity")
			break
		}
		if identity.SubjectID == "" {
			err = errors.New("expected Subject ID for DetailedFederatedIdentity")
			break
		}
		if identity.LastName == "" {
			err = errors.New("expected last name for DetailedfederatedIdentity")
			break
		}
		if identity.FirstName == "" {
			err = errors.New("expected first name for DetailedfederatedIdentity")
			break
		}
	}
	return err
}

func syncContainsIdentity(syncedIdentities []DetailedFederatedIdentity, createdIdentityUsername string) bool {
	for _, a := range syncedIdentities {
		if a.Username == createdIdentityUsername {
			return true
		}
	}
	return false
}

func ConfigureAndCreateAFederatedRealm(t *testing.T, name string) (*Realm, E3dbIdentityClient, string, map[string]string, e3dbClients.ClientConfig) {
	accountTag := uuid.New().String()
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := fmt.Sprintf("%s%d", name, time.Now().Unix())
	sovereignName := "QueenCoolName"
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)

	tozIDFederationEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		TozIDFederationEnabled: &(tozIDFederationEnabled),
	}

	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}

	requestParam := InitializeFederationConnectionRequest{
		RealmName:        realm.Name,
		FederationSource: "tozid",
	}
	response, err := identityServiceClient.InitiateFederationConnection(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error [%+v] Initiating Federation Connection for Realm %+v", err, requestParam)
	}
	if response.RealmName != realmName {
		t.Fatalf("Error Expected %+v, Recieved %+v", realmName, response.RealmName)
	}
	if response.ConnectionID == uuid.Nil {
		t.Fatalf("Error Expected a valid UUID, Recieved %+v", response.ConnectionID)
	}
	if response.APICredential == "" {
		t.Fatalf("Error Expected a credential, Recieved %+v", response.APICredential)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	credentials := make(map[string]string)
	credentials[TozIDFederationAuthHeader] = response.APICredential

	return realm, identityServiceClient, registrationToken, credentials, queenClientInfo
}

/*
func TestInitiateFederationConnectionForAuthorizedRealmReturnsSuccess(t *testing.T) {
	accountTag := uuid.New().String()
	queenClientInfo, _, err := test.MakeE3DBAccount(t, &accountServiceClient, accountTag, toznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = toznyCyclopsHost
	identityServiceClient := New(queenClientInfo)
	realmName := fmt.Sprintf("FederationConnect%d", time.Now().Unix())
	sovereignName := "QueenCoolName"
	params := CreateRealmRequest{
		RealmName:     realmName,
		SovereignName: sovereignName,
	}
	realm := createRealmWithParams(t, identityServiceClient, params)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)
	// Update Realm Setting
	tozIDFederationEnabled := true
	settingRequest := RealmSettingsUpdateRequest{
		TozIDFederationEnabled: &(tozIDFederationEnabled),
	}

	err = identityServiceClient.RealmSettingsUpdate(testContext, realmName, settingRequest)
	if err != nil {
		t.Fatalf("Error [%+v] updating realm settings for Realm %+v", err, realmName)
	}

	requestParam := InitializeFederationConnectionRequest{
		RealmName:        realm.Name,
		FederationSource: "tozid",
	}
	response, err := identityServiceClient.InitiateFederationConnection(testContext, requestParam)
	if err != nil {
		t.Fatalf("Error [%+v] Initiating Federation Connection for Realm %+v", err, requestParam)
	}
	if response.RealmName != realmName {
		t.Fatalf("Error Expected %+v, Recieved %+v", realmName, response.RealmName)
	}
	if response.ConnectionID == uuid.Nil {
		t.Fatalf("Error Expected a valid UUID, Recieved %+v", response.ConnectionID)
	}
	if response.APICredential == "" {
		t.Fatalf("Error Expected a credential, Recieved %+v", response.APICredential)
	}
}

func TestGetFederatedIdentitiesForSyncWithDetails(t *testing.T) {
	// Setup
	testName := "TestGetFederatedIdentitiesForSyncWithDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 4
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestSyncASingleFederatedIdentityWithDetails(t *testing.T) {
	// Setup
	testName := "TestSyncASingleFederatedIdentityWithDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register Identity with Realm
	identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)

	// Get the UserID of the Identity
	id, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, identity.Identity.Name)
	if err != nil {
		t.Fatalf("error %s caused by describing identity", err)
	}

	usernames := []string{id.Name}

	// No pagination necessary
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		IncludeDetails:       true,
		Credentials:          credentials,
		Usernames:            usernames,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}
	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	if len(syncResponse.FederatedIdentities) != 1 {
		t.Fatalf("Expected one Identity, got %+v", len(syncResponse.FederatedIdentities))
	}
	if syncResponse.FederatedIdentities[0].Username != usernames[0] {
		t.Fatalf("Expected User ID %+v, but received %+v", usernames[0], syncResponse.FederatedIdentities[0].Username)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

}

func TestSyncSomeFederatedIdentitiesWithDetails(t *testing.T) {
	// Setup
	testName := "TestSyncSomeFederatedIdentitiesWithDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	numberOfIdentities := 10
	var names []string
	for i := 0; i < numberOfIdentities; i++ {
		registerIdentity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
		identity, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, registerIdentity.Identity.Name)
		if err != nil {
			t.Fatalf("Error %s while describing Identity %s for Realm %s", err, registerIdentity.Identity.Name, realm.Name)
		}
		names = append(names, identity.Name)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	var usernames []string = names[0:4]
	reqParams := GetFederatedIdentitiesForSyncRequest{ // No pagination necessary
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       true,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	foundIdentities := len(syncResponse.FederatedIdentities)
	if foundIdentities != len(usernames) {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

}

func TestSyncAllFederatedIdentitiesWithNoDetails(t *testing.T) {
	// Setup
	testName := "TestSyncAllFederatedIdentitiesWithNoDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       false,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestSyncSomeFederatedIdentitiesWithNoDetails(t *testing.T) {
	// Setup
	testName := "TestSyncSomeFederatedIdentitiesWithNoDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error
	// Create and register many Identities with the Realm
	numberOfIdentities := 10
	var names []string
	for i := 0; i < numberOfIdentities; i++ {
		registerIdentity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
		identity, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, registerIdentity.Identity.Name)
		if err != nil {
			t.Fatalf("Error %s while describing Identity %s for Realm %s", err, registerIdentity.Identity.Name, realm.Name)
		}
		names = append(names, identity.Name)
	}

	// Build GetFederatedIdentitiesForSyncRequest object
	var usernames []string = names[0:4]
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       false,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	foundIdentities := len(syncResponse.FederatedIdentities)
	if foundIdentities != len(usernames) {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestSyncASingleFederatedIdentityWithNoDetails(t *testing.T) {
	// Setup
	testName := "TestSyncASingleFederatedIdentityWithNoDetails"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register Identity with Realm
	identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)

	// Get the UserID of the Identity
	id, err := identityServiceClient.DescribeIdentity(testContext, realm.Name, identity.Identity.Name)
	if err != nil {
		t.Fatalf("error %s caused by describing identity", err)
	}

	usernames := []string{id.Name}
	reqParams := GetFederatedIdentitiesForSyncRequest{
		RealmName:            realm.Name,
		Usernames:            usernames,
		IncludeDetails:       false,
		Credentials:          credentials,
		PrimaryRealmEndpoint: identityServiceClient.Host,
	}

	// Call GetFederatedIdentitiesForSync handler
	syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
	if err != nil {
		t.Fatalf("error %s while syncing federated identities", err)
	}

	if len(syncResponse.FederatedIdentities) != 1 {
		t.Fatalf("Expected one Identity, got %+v", len(syncResponse.FederatedIdentities))
	}
	if syncResponse.FederatedIdentities[0].Username != id.Name {
		t.Fatalf("Expected User ID %+v, but received %+v", id.Name, syncResponse.FederatedIdentities[0].Username)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(syncResponse.FederatedIdentities)
	if err == nil {
		t.Fatalf("Expected Identities to have no additional information from sync")
	}

}

func TestGetFederatedIdentitiesForSyncMultiplePagesOfIdentities(t *testing.T) {
	// Setup
	testName := "TestGetFederatedIdentitiesForSyncMultiplePagesOfIdentities"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 10
	perPage := 5
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
	}

	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestGetFederatedIdentitiesForSyncGetsRolesGroupsAndGroupRoleMappings(t *testing.T) {
	// Setup
	testName := "TestGetFederatedIdentitiesForSyncGetsRolesGroupsAndGroupRoleMappings"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Add Groups, Roles, and Group Role Mappings
	groupName := uniqueString("TestGetFederatedIdentitiesForSyncGetsRolesGroupsAndGroupRoleMappings Group")
	group := createRealmGroup(t, identityServiceClient, realm.Name, groupName)

	// Createe Realm Application
	application := createRealmApplication(t, identityServiceClient, realm.Name)

	// Create a Role for the Application
	roleName := uniqueString("realm application role")
	realmApplicationRole := createRealmApplicationRole(t, identityServiceClient, realm.Name, application.ID, roleName)
	groupRoleMapping, err := identityServiceClient.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	// Verify it doesn't have any assigned
	// role mappings for the application yet
	if val, ok := groupRoleMapping.ClientRoles[application.ID]; ok {
		t.Fatalf("Expected group %+v not to have role mappings %+v for application %+v", group, val, application)
	}

	// Add role mapping for application
	addRoleMappingRequest := AddGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
		RoleMapping: RoleMapping{
			ClientRoles: map[string][]Role{
				application.ID: []Role{
					*realmApplicationRole,
				},
			},
		},
	}

	err = identityServiceClient.AddGroupRoleMappings(testContext, addRoleMappingRequest)
	if err != nil {
		t.Fatalf("Error %s adding role mapping %+v to group %+v", err, addRoleMappingRequest, group)
	}
	// Verify application role mapping was added
	groupRoleMapping, err = identityServiceClient.ListGroupRoleMappings(testContext, ListGroupRoleMappingsRequest{
		RealmName: realm.Domain,
		GroupID:   group.ID,
	})
	if err != nil {
		t.Fatalf("Error %s listing role mapping for group %+v", err, group)
	}
	applicationRoleMappings, ok := groupRoleMapping.ClientRoles[application.ID]
	if !ok {
		t.Fatalf("Expected group %+v to have role mappings %+v for application %+v", group, groupRoleMapping, application)
	}
	mappedApplicationRole := applicationRoleMappings[0]
	if mappedApplicationRole.ID != realmApplicationRole.ID || mappedApplicationRole.Name != realmApplicationRole.Name || mappedApplicationRole.Description != realmApplicationRole.Description {
		t.Fatalf("Expected mapped group application role %+v to equal application group role %+v", mappedApplicationRole, realmApplicationRole)
	}

	// Make Identities
	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	for i := 0; i < numberOfIdentities; i++ {
		identityResponse := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
		groupID := []string{group.ID}
		updateGroupMembership(t, identityServiceClient, "update", realm.Name, identityResponse.Identity.ToznyID.String(), groupID)
	}

	// Call GetFederatedIdentitiesForSync handler
	var totalIdentities []DetailedFederatedIdentity
	first := 0
	for i := 0; i < pages; i++ {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                perPage, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken
		if len(syncResponse.FederatedIdentities) != perPage {
			t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, perPage, len(syncResponse.FederatedIdentities))
		}
		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	// Confirm we receive the Groups, Roles, and Group Role Mappings of an Identity
	identity := totalIdentities[0]
	if identity.Group[0].ID != group.ID {
		t.Fatalf("Expected synced Identity to have the same group")
	}

	identityApplicationRoleMappings, ok := identity.GroupRoleMappings[0].ClientRoles[application.ID]
	if !ok {
		t.Fatalf("Expected Identity %+v to have role mappings %+v for application %+v", identity, identity.GroupRoleMappings[0], application)
	}
	mappedApplicationRoleForIdentity := identityApplicationRoleMappings[0]
	if mappedApplicationRoleForIdentity.ID != realmApplicationRole.ID || mappedApplicationRoleForIdentity.Name != realmApplicationRole.Name || mappedApplicationRoleForIdentity.Description != realmApplicationRole.Description {
		t.Fatalf("Expected Identity %+v to have mapped group application role  %+v to equal application group role %+v", identity, mappedApplicationRole, realmApplicationRole)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}
}

func TestGetFederatedIdentitiesForSyncLimitSetToOneNoRepeatsOrSkips(t *testing.T) {
	// Setup
	testName := "TestGetFederatedIdentitiesForSyncLimitSetToOneNoRepeatsOrSkips"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	var createdIdentities []*RegisterIdentityResponse
	for i := 0; i < numberOfIdentities; i++ {
		identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
		createdIdentities = append(createdIdentities, identity)
	}

	first := 0
	max := 1
	for first != -1 {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                max, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken

		// Avoids the case in which next token is -1, so synced Identities is 0
		if first != 0 {
			if len(syncResponse.FederatedIdentities) != max {
				t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, max, len(syncResponse.FederatedIdentities))
			}
		}

		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)

		if first == 0 {
			first = -1
		}
	}

	if first != -1 {
		t.Fatalf("Expected next token to be -1, but received %d", first)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

	// Verify that we received every Identity and that there were no repeats
	for _, i := range createdIdentities {
		if !syncContainsIdentity(totalIdentities, i.Identity.Name) {
			t.Fatalf("Expected sync to contain Identity %+v", i)
		}
	}
}

func TestGetFederatedIdentitiesForSyncLimitSetToTwoNoRepeatsOrSkips(t *testing.T) {
	// Setup
	testName := "TestGetFederatedIdentitiesForSyncLimitSetToTwoNoRepeatsOrSkips"
	realm, identityServiceClient, registrationToken, credentials, clientConfig := ConfigureAndCreateAFederatedRealm(t, testName)
	defer identityServiceClient.DeleteRealm(testContext, realm.Name)

	var totalIdentities []DetailedFederatedIdentity
	var syncResponse *GetFederatedIdentitiesForSyncResponse
	var err error

	// Create and register many Identities with the Realm
	pages := 1
	perPage := 50
	numberOfIdentities := pages * perPage
	var createdIdentities []*RegisterIdentityResponse
	for i := 0; i < numberOfIdentities; i++ {
		identity := createIdentityAndRegisterWithRealm(t, realm, registrationToken, clientConfig)
		createdIdentities = append(createdIdentities, identity)
	}

	first := 0
	max := 2
	for first != -1 {
		reqParams := GetFederatedIdentitiesForSyncRequest{
			RealmName:            realm.Name,
			IncludeDetails:       true,
			Limit:                max, // For this test we get all Identities in a single request
			NextToken:            first,
			Credentials:          credentials,
			PrimaryRealmEndpoint: identityServiceClient.Host,
		}

		syncResponse, err = identityServiceClient.GetFederatedIdentitiesForSync(testContext, reqParams)
		if err != nil {
			t.Fatalf("error %s while syncing federated identities", err)
		}
		first = syncResponse.NextToken

		// Avoids the case in which next token is -1, so synced Identities is 0
		if first != 0 {
			if len(syncResponse.FederatedIdentities) != max {
				t.Fatalf("Identity count incorrect with first %d in realm %q mismatch, expected %d, got %d", first, realm.Name, max, len(syncResponse.FederatedIdentities))
			}
		}

		totalIdentities = append(totalIdentities, syncResponse.FederatedIdentities...)

		if first == 0 {
			first = -1
		}
	}

	if first != -1 {
		t.Fatalf("Expected next token to be -1, but received %d", first)
	}

	foundIdentities := len(totalIdentities)
	if foundIdentities != numberOfIdentities {
		t.Fatalf("Expected to find %+v identities. Found %+v\n", numberOfIdentities, foundIdentities)
	}

	err = VerifyIncludeDetailsForDetailedIdentity(totalIdentities)
	if err != nil {
		t.Fatalf("Error: %s. Expected Identities to have additional information from sync", err)
	}

	// Verify that we received every Identity and that there were no repeats
	for _, i := range createdIdentities {
		if !syncContainsIdentity(totalIdentities, i.Identity.Name) {
			t.Fatalf("Expected sync to contain Identity %+v", i)
		}
	}
}
*/
