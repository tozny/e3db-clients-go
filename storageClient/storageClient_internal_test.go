package storageClient_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
	"github.com/tozny/e3db-clients-go/accountClient"
	"github.com/tozny/e3db-clients-go/storageClient"
	storageClientV2 "github.com/tozny/e3db-clients-go/storageClient"
	"github.com/tozny/e3db-clients-go/test"
)

var (
	internalClientServiceHost                 = os.Getenv("CLIENT_SERVICE_HOST")
	internalTestCtx                           = context.Background()
	internalToznyCyclopsHost                  = os.Getenv("TOZNY_CYCLOPS_SERVICE_HOST")
	internalE3dbAuthHost                      = os.Getenv("E3DB_AUTH_SERVICE_HOST")
	internalE3dbAccountHost                   = os.Getenv("E3DB_ACCOUNT_SERVICE_HOST")
	internalE3dbAPIKey                        = os.Getenv("E3DB_API_KEY_ID")
	internalE3dbAPISecret                     = os.Getenv("E3DB_API_KEY_SECRET")
	internalE3dbClientID                      = os.Getenv("E3DB_CLIENT_ID")
	InternalInternalBootstrapPublicSigningKey = os.Getenv("BOOTSTRAP_CLIENT_PUBLIC_SIGNING_KEY")
	InternalBootstrapPrivateSigningKey        = os.Getenv("BOOTSTRAP_CLIENT_PRIVATE_SIGNING_KEY")
	InternalValidAccountClientConfig          = e3dbClients.ClientConfig{
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbAccountHost,
		AuthNHost: internalE3dbAuthHost,
	}
	internalE3dbIdentityHost         = internalToznyCyclopsHost
	InternalBootIdentityClientConfig = e3dbClients.ClientConfig{
		ClientID:  internalE3dbClientID,
		APIKey:    internalE3dbAPIKey,
		APISecret: internalE3dbAPISecret,
		Host:      internalE3dbIdentityHost,
		AuthNHost: internalE3dbAuthHost,
		SigningKeys: e3dbClients.SigningKeys{
			Public: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalInternalBootstrapPublicSigningKey,
			},
			Private: e3dbClients.Key{
				Type:     e3dbClients.DefaultSigningKeyType,
				Material: InternalBootstrapPrivateSigningKey,
			},
		},
	}
	InternalBootstrapClient = storageClientV2.New(InternalBootIdentityClientConfig)
)

func TestInternalGetNoteInfo(t *testing.T) {
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: internalToznyCyclopsHost})
	queenClientConfig, _, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), internalToznyCyclopsHost)
	if err != nil {
		t.Fatalf("Could not register account %s\n", err)
	}
	client := storageClientV2.New(queenClientConfig)
	if err != nil {
		t.Fatalf("Could not parse client ID. clientID: %s, err: %s", client.ClientID, err)
	}
	queenStorage := storageClientV2.New(queenClientConfig)
	data := make(map[string]string)
	data["test"] = "values"

	generatedNote, err := internalGenerateNote(queenClientConfig.SigningKeys.Public.Material, queenClientConfig)
	if err != nil {
		t.Fatalf("Failed to generate new note %+v", err)
	}

	noteName := "name" + uuid.New().String()
	generatedNote.IDString = noteName

	writtenNote, err := queenStorage.WriteNote(internalTestCtx, *generatedNote)
	if err != nil {
		t.Fatalf("Failed to write new generatedNote %+v", err)
	}

	noteInfo, err := InternalBootstrapClient.InternalGetNoteInfo(internalTestCtx, writtenNote.IDString)
	if err != nil {
		t.Fatalf("An error occurred during internal read note info. Error: %v", err)
	}

	if noteInfo.PublicRecipientSigningKey != writtenNote.RecipientSigningKey {
		t.Fatalf("Expected recipient signing keys to be the same.")
	}
}

// TestInternalMembershiFetchClientWithNoGroupsReturnsSuccess
func TestInternalMembershipFetchReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: internalToznyCyclopsHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), internalToznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = internalToznyCyclopsHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClientWithAccountService(internalTestCtx, internalClientServiceHost, internalE3dbAccountHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	reg, ClientConfig2, err := test.RegisterClientWithAccountService(internalTestCtx, internalClientServiceHost, internalE3dbAccountHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = internalToznyCyclopsHost
	ClientConfig2.Host = internalToznyCyclopsHost
	// Clients to Add to Group
	groupMemberToAdd1 := storageClient.New(ClientConfig)
	groupMemberToAdd2 := storageClient.New(ClientConfig2)
	queenClient := storageClient.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClient.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(internalTestCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key for client1
	membershipKeyRequest := storageClient.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd1.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(internalTestCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}
	//Create a request to create a new membership key for client2
	membershipKeyRequest2 := storageClient.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd2.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse2, err := queenClient.CreateGroupMembershipKey(internalTestCtx, membershipKeyRequest2)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}
	// Add clients  to group
	groupMemberCapabilities := []string{storageClient.ShareContentGroupCapability, storageClient.ReadContentGroupCapability}
	memberRequest := []storageClient.GroupMember{}
	//Adding First Client to Request
	memberRequest = append(memberRequest,
		storageClient.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd1.ClientID),
			MembershipKey:   membershipKeyResponse,
			CapabilityNames: groupMemberCapabilities})
	//Adding Second client to request
	memberRequest = append(memberRequest,
		storageClient.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd2.ClientID),
			MembershipKey:   membershipKeyResponse2,
			CapabilityNames: groupMemberCapabilities})

	addMemberRequest := storageClient.AddGroupMembersRequest{
		GroupID:      response.GroupID,
		GroupMembers: memberRequest,
	}
	_, err = queenClient.AddGroupMembers(internalTestCtx, addMemberRequest)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", addMemberRequest, err)
	}
	// Get internal call
	param := storageClient.InternalFetchClientMembership{
		ClientID:     uuid.MustParse(groupMemberToAdd1.ClientID),
		Capabilities: groupMemberCapabilities,
	}
	fetchResponse, err := InternalBootstrapClient.InternalClientGroupMembershipFetch(internalTestCtx, param)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", param, err)
	}
	for _, groups := range fetchResponse.Groups {
		found := false
		for _, capability := range groupMemberCapabilities {
			if groups.Capability == capability {
				found = true
			}
		}
		if !found {
			t.Fatalf("Failed to Fetch Group Member Correctly: Request:  %+v Response: %+v", groupMemberCapabilities, fetchResponse)
		}
	}

	param = storageClient.InternalFetchClientMembership{
		ClientID:     uuid.MustParse(groupMemberToAdd2.ClientID),
		Capabilities: groupMemberCapabilities,
	}
	fetchResponse2, err := InternalBootstrapClient.InternalClientGroupMembershipFetch(internalTestCtx, param)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", param, err)
	}
	for _, groups := range fetchResponse2.Groups {
		found := false
		for _, capability := range groupMemberCapabilities {
			if groups.Capability == capability {
				found = true
			}
		}
		if !found {
			t.Fatalf("Failed to Fetch Group Member Correctly: Request:  %+v Response: %+v", groupMemberCapabilities, fetchResponse)
		}
	}
}

func TestInternalMembershiFetchClientWithNoCapabilitiesReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: internalToznyCyclopsHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), internalToznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = internalToznyCyclopsHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClientWithAccountService(internalTestCtx, internalClientServiceHost, internalE3dbAccountHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = internalToznyCyclopsHost
	groupMemberToAdd := storageClient.New(ClientConfig)
	queenClient := storageClient.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClient.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(internalTestCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key
	membershipKeyRequest := storageClient.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(internalTestCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}

	// Add client to group
	groupMemberCapabilities := []string{storageClient.ShareContentGroupCapability, storageClient.ReadContentGroupCapability}
	memberRequest := []storageClient.GroupMember{}
	memberRequest = append(memberRequest,
		storageClient.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd.ClientID),
			MembershipKey:   membershipKeyResponse,
			CapabilityNames: groupMemberCapabilities})

	addMemberRequest := storageClient.AddGroupMembersRequest{
		GroupID:      response.GroupID,
		GroupMembers: memberRequest,
	}
	addToGroupResponse, err := queenClient.AddGroupMembers(internalTestCtx, addMemberRequest)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", addMemberRequest, err)
	}
	for _, requestGroupMember := range addMemberRequest.GroupMembers {
		var found bool
		for _, responseGroupMember := range *addToGroupResponse {
			if responseGroupMember.ClientID == requestGroupMember.ClientID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to add correct Group Members: Response( %+v) \n", addToGroupResponse)
		}
	}
	// Get internal call
	param := storageClient.InternalFetchClientMembership{
		ClientID: uuid.MustParse(groupMemberToAdd.ClientID),
	}
	fetchResponse, err := InternalBootstrapClient.InternalClientGroupMembershipFetch(internalTestCtx, param)
	if err != nil {
		t.Fatalf("Failed to fetch Group member groups: Request:  %+v Err: %+v", param, err)
	}
	if len(fetchResponse.Groups) != 0 {
		t.Fatalf("Requested no capability, expected no groups recieved  %+v", fetchResponse)
	}
}
func TestInternalMembershiFetchClientWithNoGroupsReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: internalToznyCyclopsHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), internalToznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = internalToznyCyclopsHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClientWithAccountService(internalTestCtx, internalClientServiceHost, internalE3dbAccountHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = internalToznyCyclopsHost
	nonGroupMember := storageClient.New(ClientConfig)
	// Get internal call
	param := storageClient.InternalFetchClientMembership{
		ClientID:     uuid.MustParse(nonGroupMember.ClientID),
		Capabilities: []string{storageClient.ManageMembershipGroupCapability},
	}
	fetchResponse, err := InternalBootstrapClient.InternalClientGroupMembershipFetch(internalTestCtx, param)
	if err != nil {
		t.Fatalf("Failed to fetch Group member groups: Request:  %+v Err: %+v", param, err)
	}
	for _, groups := range fetchResponse.Groups {
		if groups.Capability == storageClient.ManageMembershipGroupCapability {
			if len(groups.GroupIDs) != 0 {
				t.Fatalf("Client has no groups with this capability, expected no groups, recieved  %+v", fetchResponse)
			}
		} else {
			t.Fatalf("Requested only one capability, recieved  %+v", fetchResponse)
		}
	}
}
func TestInternalMembershipFetchClientWithCapabilitiesMemberNotApartofReturnsSuccess(t *testing.T) {
	// Create Clients for this test
	registrationClient := accountClient.New(e3dbClients.ClientConfig{Host: internalToznyCyclopsHost})
	queenClientInfo, createAccountResponse, err := test.MakeE3DBAccount(t, &registrationClient, uuid.New().String(), internalToznyCyclopsHost)
	if err != nil {
		t.Fatalf("Error %s making new account", err)
	}
	queenClientInfo.Host = internalToznyCyclopsHost
	accountToken := createAccountResponse.AccountServiceToken
	queenAccountClient := accountClient.New(queenClientInfo)
	registrationToken, err := test.CreateRegistrationToken(&queenAccountClient, accountToken)
	if err != nil {
		t.Fatalf("error %s creating account registration token using %+v %+v", err, queenAccountClient, accountToken)
	}
	reg, ClientConfig, err := test.RegisterClientWithAccountService(internalTestCtx, internalClientServiceHost, internalE3dbAccountHost, registrationToken, "name")
	if err != nil {
		t.Fatalf("Error registering Client %+v %+v %+v ", reg, err, ClientConfig)
	}
	ClientConfig.Host = internalToznyCyclopsHost
	groupMemberToAdd := storageClient.New(ClientConfig)
	queenClient := storageClient.New(queenClientInfo)
	// Generate a Key pair for the group
	encryptionKeyPair, err := e3dbClients.GenerateKeyPair()
	if err != nil {
		t.Errorf("Failed generating encryption key pair %s", err)
		return
	}
	// encrypt the created private key for groups
	eak, err := e3dbClients.EncryptPrivateKey(encryptionKeyPair.Private, queenClient.EncryptionKeys)
	if err != nil {
		t.Errorf("Failed generating encrypted group key  %s", err)
	}
	// Create a new group to give membership key for the client
	newGroup := storageClient.CreateGroupRequest{
		Name:              "TestGroup1" + uuid.New().String(),
		PublicKey:         encryptionKeyPair.Public.Material,
		EncryptedGroupKey: eak,
	}
	response, err := queenClient.CreateGroup(internalTestCtx, newGroup)
	if err != nil {
		t.Fatalf("Failed to create group \n Group( %+v) \n error %+v", newGroup, err)
	}
	if response.Name != newGroup.Name {
		t.Fatalf("Group name (%+v) passed in, does not match Group name (%+v) inserted for Group( %+v) \n", newGroup.Name, response.Name, newGroup)
	}
	//Create a request to create a new membership key
	membershipKeyRequest := storageClient.CreateMembershipKeyRequest{
		GroupAdminID:      queenClient.ClientID,
		NewMemberID:       groupMemberToAdd.ClientID,
		EncryptedGroupKey: response.EncryptedGroupKey,
		ShareePublicKey:   queenClient.EncryptionKeys.Public.Material,
	}
	membershipKeyResponse, err := queenClient.CreateGroupMembershipKey(internalTestCtx, membershipKeyRequest)
	if err != nil {
		t.Fatalf("Failed to create membership key \n response %+v \n error %+v", membershipKeyResponse, err)
	}

	// Add client to group
	groupMemberCapabilities := []string{storageClient.ShareContentGroupCapability, storageClient.ReadContentGroupCapability}
	memberRequest := []storageClient.GroupMember{}
	memberRequest = append(memberRequest,
		storageClient.GroupMember{
			ClientID:        uuid.MustParse(groupMemberToAdd.ClientID),
			MembershipKey:   membershipKeyResponse,
			CapabilityNames: groupMemberCapabilities})

	addMemberRequest := storageClient.AddGroupMembersRequest{
		GroupID:      response.GroupID,
		GroupMembers: memberRequest,
	}
	addToGroupResponse, err := queenClient.AddGroupMembers(internalTestCtx, addMemberRequest)
	if err != nil {
		t.Fatalf("Failed to Add Group Member to Group: Request:  %+v Err: %+v", addMemberRequest, err)
	}
	for _, requestGroupMember := range addMemberRequest.GroupMembers {
		var found bool
		for _, responseGroupMember := range *addToGroupResponse {
			if responseGroupMember.ClientID == requestGroupMember.ClientID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Failed to add correct Group Members: Response( %+v) \n", addToGroupResponse)
		}
	}
	// Get internal call
	param := storageClient.InternalFetchClientMembership{
		ClientID:     uuid.MustParse(groupMemberToAdd.ClientID),
		Capabilities: []string{storageClient.ManageMembershipGroupCapability},
	}
	fetchResponse, err := InternalBootstrapClient.InternalClientGroupMembershipFetch(internalTestCtx, param)
	if err != nil {
		t.Fatalf("Failed to fetch Group member groups: Request:  %+v Err: %+v", param, err)
	}
	for _, groups := range fetchResponse.Groups {
		if groups.Capability == storageClient.ManageMembershipGroupCapability {
			if len(groups.GroupIDs) != 0 {
				t.Fatalf("Client has no groups with this capability, expected no groups, recieved  %+v", fetchResponse)
			}
		} else {
			t.Fatalf("Requested only one capability, recieved  %+v", fetchResponse)
		}
	}
}

func internalGenerateNote(recipientSigningKey string, clientConfig e3dbClients.ClientConfig) (*storageClientV2.Note, error) {
	rawData := map[string]string{
		"key1": "rawnote",
		"key2": "unprocessednote",
		"key3": "organicnote",
	}
	ak := e3dbClients.RandomSymmetricKey()
	eak, err := e3dbClients.EncryptAccessKey(ak, clientConfig.EncryptionKeys)
	if err != nil {
		return nil, err
	}
	encryptedData := e3dbClients.EncryptData(rawData, ak)

	return &storageClientV2.Note{
		Mode:                "Sodium",
		RecipientSigningKey: recipientSigningKey,
		WriterSigningKey:    clientConfig.SigningKeys.Public.Material,
		WriterEncryptionKey: clientConfig.EncryptionKeys.Public.Material,
		EncryptedAccessKey:  eak,
		Type:                "Integration Test",
		Data:                *encryptedData,
		Plain:               map[string]string{"extra1": "not encrypted", "extra2": "more plain data"},
		Signature:           "signed",
		MaxViews:            5,
	}, err
}
