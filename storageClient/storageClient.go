package storageClient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/tozny/e3db-clients-go/authClient"
	"github.com/tozny/e3db-clients-go/clientServiceClient"
	"github.com/tozny/e3db-clients-go/request"

	"github.com/google/uuid"
	e3dbClients "github.com/tozny/e3db-clients-go"
)

const (
	storageServiceBasePath = "/v2/storage"
	EmailOTPQueryParam     = "email_otp"
	ToznyOTPQueryParam     = "tozny_otp"
	// The TozID JWT signed OIDC ID token issued as part of a valid TozID realm login session that contains the one time password as the `nonce` claim and TozID as the authorizing party (`azp`) claim.
	TozIDLoginTokenHeader           = "X-TOZID-LOGIN-TOKEN"
	ReadContentGroupCapability      = "READ_CONTENT"
	ShareContentGroupCapability     = "SHARE_CONTENT"
	ManageMembershipGroupCapability = "MANAGE_MEMBERSHIP"
)

var (
	// The EACP params to set as a request
	EACPHeaders = []string{TozIDLoginTokenHeader}
)

// StorageClient implements an http client for communication with the storage service.
type StorageClient struct {
	ClientID       string
	SigningKeys    e3dbClients.SigningKeys
	EncryptionKeys e3dbClients.EncryptionKeys
	Host           string // host will generally need to be cyclops service to get the X-Tozny-Auth header
	httpClient     *http.Client
	*authClient.E3dbAuthClient
	requester request.Requester
}

// SignNote signs a note using using the provided private signing key and salt
// according to the Tozny Field Signing V1 protocol using Blake2B for hashing and curve Ed25519 for signing
// https://github.com/tozny/internal-docs/blob/master/tozny-platform/notes/tozny-field-signing.md
// returning the signed note and error (if any).
func (c *StorageClient) SignNote(note Note, privateSigningKey e3dbClients.SigningKey, salt string) (Note, error) {
	// Sign the signing material (key and salt)
	signatureSalt := uuid.New().String()
	signerSignature, err := e3dbClients.SignField("signature", salt, privateSigningKey, signatureSalt)
	if err != nil {
		return note, err
	}
	note.Signature = signerSignature
	// Sign each field in the note data individually using the same signed signing material
	for key, value := range note.Data {
		signedNoteField, err := e3dbClients.SignField(key, value, privateSigningKey, salt)
		if err != nil {
			return note, err
		}
		note.Data[key] = signedNoteField
	}

	return note, nil
}

// DecryptNote in place decrypts a note's data. This method is not idempotent and will error if called multiple times.
func (c *StorageClient) DecryptNote(note *Note) error {
	privateKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return err
	}
	ak, err := e3dbClients.DecryptEAK(note.EncryptedAccessKey, note.WriterEncryptionKey, privateKey)
	if err != nil {
		return err
	}
	writerPublicSigningKey, err := e3dbClients.PublicSigningKeyFromEncodedString(note.WriterSigningKey)
	if err != nil {
		return err
	}

	signatureSalt, err := e3dbClients.VerifyField("signature", note.Signature, writerPublicSigningKey, "")
	if err != nil {
		return err
	}
	decryptedData, err := e3dbClients.DecryptSignedData(note.Data, ak, writerPublicSigningKey, signatureSalt)
	if err != nil {
		return err
	}
	note.Data = decryptedData
	return nil
}

// WriteNote writes the specified note to the server using PUT, returning the written note and error (if any)
func (c *StorageClient) PutNote(ctx context.Context, params Note) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// WriteNote writes the specified note to the server, returning the written note and error (if any)
func (c *StorageClient) WriteNote(ctx context.Context, params Note) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// CreateGroup creates a group using the specified parameters,
// returning the created group and error (if any).
func (c *StorageClient) CreateGroup(ctx context.Context, params CreateGroupRequest) (*Group, error) {
	var result *Group
	path := c.Host + storageServiceBasePath + "/groups"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// DescribeGroup fetches a group using the specified parameters,
// returning the group and error (if any).
func (c *StorageClient) DescribeGroup(ctx context.Context, params DescribeGroupRequest) (*Group, error) {
	var result *Group
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String()
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}

	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// DeleteGroup deletes a specified group, returning an error (if any).
func (c *StorageClient) DeleteGroup(ctx context.Context, params DeleteGroupRequest) error {
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String()
	req, err := e3dbClients.CreateRequest("DELETE", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

// ListGroups returns all groups for the client's account by default or optionally filter by parameters such as client ID, group name
func (c *StorageClient) ListGroups(ctx context.Context, params ListGroupsRequest) (*ListGroupsResponse, error) {
	var result *ListGroupsResponse
	path := c.Host + storageServiceBasePath + "/groups"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("nextToken", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("max", strconv.Itoa(int(params.Max)))
	if params.ClientID != uuid.Nil {
		urlParams.Set("client_id", params.ClientID.String())
	}
	for _, groupName := range params.GroupNames {
		urlParams.Add("group_names", groupName)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// AddGroupMembers Adds Clients to a group and returns the successfully added clients (if any).
func (c *StorageClient) AddGroupMembers(ctx context.Context, params AddGroupMembersRequest) (*[]GroupMember, error) {
	var result *[]GroupMember
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/members"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}

	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// UpdateGroupMembersMembership updates clients group membership capabilties
func (c *StorageClient) UpdateGroupMembersMembership(ctx context.Context, params UpdateGroupMembersRequest) (*[]GroupMemberMembershipUpdate, error) {
	var result *[]GroupMemberMembershipUpdate
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/members"
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// UpdateGroupDescription updates a TozStore group's description and returns the updated group.
func (c *StorageClient) UpdateGroupDescription(ctx context.Context, params UpdateGroupRequest) (*Group, error) {
	var result *Group
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String()
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}

	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// DeleteGroupMembers removed clients form a group and returns success.
func (c *StorageClient) DeleteGroupMembers(ctx context.Context, params DeleteGroupMembersRequest) error {
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/members"
	req, err := e3dbClients.CreateRequest("DELETE", path, params)
	if err != nil {
		return err
	}

	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

// InternalDeleteGroupMembers removes member from tozstore group.
func (c *StorageClient) InternalDeleteGroupMembers(ctx context.Context, groupId string, params SSInternalDeleteGroupMember) error {
	path := c.Host + "/internal" + storageServiceBasePath + "/groups/" + groupId + "/members"
	req, err := e3dbClients.CreateRequest("DELETE", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

// ListGroupMembers returns the group members and capabilities based on the groupID
func (c *StorageClient) ListGroupMembers(ctx context.Context, params ListGroupMembersRequest) (*ListGroupMembersResponse, error) {
	var result *ListGroupMembersResponse
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/members"
	request, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := request.URL.Query()
	urlParams.Set("nextToken", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("max", strconv.Itoa(int(params.Max)))
	request.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, request, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GetBulkRecordsSharedWithGroups returns a map of all records shared with a group and the corresponding group ID
func (c *StorageClient) BulkListGroupMembers(ctx context.Context, params BulkListGroupMembersRequest) (*BulkListGroupMembersResponse, error) {
	var result *BulkListGroupMembersResponse
	path := c.Host + storageServiceBasePath + "/groups/bulk/members"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	for _, group := range params.GroupIDs {
		urlParams.Add("group_ids", group)
	}
	urlParams.Set("nextToken", params.NextToken)
	urlParams.Set("max", strconv.Itoa(int(params.Max)))
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) UpsertNoteByIDString(ctx context.Context, params Note) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("PUT", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// CreateGroupMembershipKey creates an encrypted version of the provided groupkey for the specified group member.
func (c *StorageClient) CreateGroupMembershipKey(ctx context.Context, params CreateMembershipKeyRequest) (string, error) {
	var wrappedEncryptedMembershipKey string
	// Decrypt the access key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return wrappedEncryptedMembershipKey, err
	}
	groupKey, err := e3dbClients.DecryptEAK(params.EncryptedGroupKey, params.ShareePublicKey, rawEncryptionKey)
	if err != nil {
		return wrappedEncryptedMembershipKey, err
	}
	// Using the decrypted version of
	// encrypted Group Key and the public key of
	// the group admin specified in params,
	// create an encrypted membership key that
	// the new member can decrypt
	wrappedEncryptedMembershipKey, err = c.EncryptMembershipKeyForGroupMember(ctx, groupKey, params.NewMemberID)
	return wrappedEncryptedMembershipKey, err
}

// EncryptMembershipKeyForGroupMember tales the group key and wraps it for the new client
func (c *StorageClient) EncryptMembershipKeyForGroupMember(ctx context.Context, groupKey e3dbClients.SymmetricKey, newMemberID string) (string, error) {
	var wrappedMembershipKey string
	clientServiceConfig := e3dbClients.ClientConfig{
		APIKey:    c.APIKey,
		APISecret: c.APISecret,
		Host:      c.Host,
		AuthNHost: c.Host,
	}
	clientClient := clientServiceClient.New(clientServiceConfig)
	publicClient, err := clientClient.GetPublicClient(ctx, newMemberID)
	if err != nil {
		return wrappedMembershipKey, err
	}
	newMemberPubKey := publicClient.PublicClient.PublicKeys[e3dbClients.DefaultEncryptionKeyType]
	// Use the group admin private key for signing (to allow this client to sign the key)
	// and the new member public key for encryption (to allow the reader to decrypt)
	encryptionKeys := e3dbClients.EncryptionKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: newMemberPubKey,
		},
		Private: c.EncryptionKeys.Private,
	}
	eak, eakN, err := e3dbClients.BoxEncryptToBase64(groupKey[:], encryptionKeys)
	if err != nil {
		return wrappedMembershipKey, err
	}
	wrappedMembershipKey = fmt.Sprintf("%s.%s", eak, eakN)
	return wrappedMembershipKey, nil

}

// GetGroupMembershipKey returns the client's group information including the membership key.
func (c *StorageClient) GetGroupMembershipKey(ctx context.Context, params GetMembershipKeyRequest) (*ClientGroup, error) {
	var result *ClientGroup
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/membership_key"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// CreateGroupAccessKey takes in information about a record type and wraps the access key for a group.
func (c *StorageClient) CreateGroupAccessKey(ctx context.Context, params GroupAccessKeyRequest) (e3dbClients.SymmetricKey, string, error) {
	var wrappedAccessKey string
	var accessKey e3dbClients.SymmetricKey
	// Decrypt Access Key
	rawEncryptionKey, err := e3dbClients.DecodeSymmetricKey(c.EncryptionKeys.Private.Material)
	if err != nil {
		return accessKey, wrappedAccessKey, err
	}
	accessKey, err = e3dbClients.DecryptEAK(params.EncryptedAccessKey, c.EncryptionKeys.Public.Material, rawEncryptionKey)
	if err != nil {
		return accessKey, wrappedAccessKey, err
	}
	// Encrypt Access Key with Group's Public Key
	encryptionKeys := e3dbClients.EncryptionKeys{
		Public: e3dbClients.Key{
			Type:     e3dbClients.DefaultEncryptionKeyType,
			Material: params.PublicKey,
		},
		Private: c.EncryptionKeys.Private,
	}
	eak, eakN, err := e3dbClients.BoxEncryptToBase64(accessKey[:], encryptionKeys)
	if err != nil {
		return accessKey, wrappedAccessKey, err
	}
	wrappedAccessKey = fmt.Sprintf("%s.%s", eak, eakN)
	return accessKey, wrappedAccessKey, nil
}

// ShareRecordWithGroup shares a record type for all group members in given group
func (c *StorageClient) ShareRecordWithGroup(ctx context.Context, params ShareGroupRecordRequest) (*ShareGroupRecordResponse, error) {
	var result *ShareGroupRecordResponse
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/share"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// RemoveSharedRecordWithGroup shares a record type for all group members in given group
func (c *StorageClient) RemoveSharedRecordWithGroup(ctx context.Context, params RemoveRecordSharedWithGroupRequest) error {
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/share"
	req, err := e3dbClients.CreateRequest("DELETE", path, params)
	if err != nil {
		return err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

// GetSharedWithGroup returns a list of all records shared with a group
func (c *StorageClient) GetSharedWithGroup(ctx context.Context, params ListGroupRecordsRequest) (*ListGroupRecordsResponse, error) {
	var result *ListGroupRecordsResponse
	path := c.Host + storageServiceBasePath + "/groups/" + params.GroupID.String() + "/share"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("next_token", params.NextToken)
	if params.Max != 0 {
		urlParams.Set("max", strconv.Itoa(int(params.Max)))
	}
	for _, writer := range params.WriterIDs {
		urlParams.Add("writer_ids", writer)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GetBulkRecordsSharedWithGroups returns a map of all records shared with a group and the corresponding group ID
func (c *StorageClient) GetBulkRecordsSharedWithGroups(ctx context.Context, params BulkListGroupRecordsRequest) (*BulkListGroupRecordsResponse, error) {
	var result *BulkListGroupRecordsResponse
	path := c.Host + storageServiceBasePath + "/groups/bulk/share"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("next_token", params.NextToken)
	if params.Max != 0 {
		urlParams.Set("max", strconv.Itoa(int(params.Max)))
	}
	for _, group := range params.GroupIDs {
		urlParams.Add("group_ids", group)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// ReadNote retrieves a note by noteID
func (c *StorageClient) ReadNote(ctx context.Context, noteID string, eacpParams map[string]string) (*Note, error) {
	return c.readNote(ctx, "", noteID, eacpParams)
}

// ReadNoteByName retrieves a note by name (id_string)
func (c *StorageClient) ReadNoteByName(ctx context.Context, noteName string, eacpParams map[string]string) (*Note, error) {
	return c.readNote(ctx, noteName, "", eacpParams)
}

func (c *StorageClient) readNote(ctx context.Context, noteName string, noteID string, eacpParams map[string]string) (*Note, error) {
	var result *Note
	path := c.Host + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	// Set appropriate request query params & headers for satisfying
	// a note's required EACPs
	urlParams := req.URL.Query()
	for key, val := range eacpParams {
		var isHeaderEACP bool
		for _, eacpHeader := range EACPHeaders {
			if key == eacpHeader {
				isHeaderEACP = true
				break
			}
		}
		if isHeaderEACP {
			req.Header.Add(key, val)
		} else {
			urlParams.Set(key, val)
		}
	}

	if noteName != "" && noteID != "" {
		return result, errors.New("readNote: noteName and noteID may not be set at the same time")
	}
	if noteName != "" {
		urlParams.Set("id_string", noteName)
	}
	if noteID != "" {
		urlParams.Set("note_id", noteID)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) Challenge(ctx context.Context, noteID string, params ChallengeRequest) (ChallengeResponse, error) {
	var challenges ChallengeResponse
	path := c.Host + storageServiceBasePath + "/notes/challenge"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return challenges, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("note_id", noteID)
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &challenges)
	return challenges, err
}

// ProxyChallengeByName allows a service to send an already authenticated request
// to the Storage service to trigger a note challenge by name.
func (c *StorageClient) ProxyChallengeByName(ctx context.Context, headers http.Header, noteName string, params ChallengeRequest) (ChallengeResponse, error) {
	var challenges ChallengeResponse
	path := c.Host + storageServiceBasePath + "/notes/challenge"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return challenges, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("id_string", noteName)
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeProxiedSignedCall(ctx, c.requester, headers, req, &challenges)
	return challenges, err
}

// InternalProxyChallengeByName allows a service to send an internal request
// to the Storage service to save a note challenge by name.
func (c *StorageClient) InternalChallengeByName(ctx context.Context, headers http.Header, noteName string, params ChallengeRequest) (ChallengeResponse, error) {
	var challenges ChallengeResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/notes/challenge"
	req, err := e3dbClients.CreateRequest("PATCH", path, params)
	if err != nil {
		return challenges, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("id_string", noteName)
	req.URL.RawQuery = urlParams.Encode()
	// err = e3dbClients.MakeProxiedSignedCall(ctx, c.requester, headers, req, &challenges)
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &challenges)
	return challenges, err
}

func (c *StorageClient) Prime(ctx context.Context, noteID string, body PrimeRequestBody) (PrimeResponseBody, error) {
	path := c.Host + storageServiceBasePath + "/notes/prime"
	req, err := e3dbClients.CreateRequest("PATCH", path, body)
	var primedResponse PrimeResponseBody
	if err != nil {
		return primedResponse, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("note_id", noteID)
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &primedResponse)
	return primedResponse, err
}

// PrimeByNoteName primes the note with the provided noteName
func (c *StorageClient) PrimeByNoteName(ctx context.Context, noteName string, body PrimeRequestBody) (PrimeResponseBody, error) {
	path := c.Host + storageServiceBasePath + "/notes/prime"
	req, err := e3dbClients.CreateRequest("PATCH", path, body)
	var primedResponse PrimeResponseBody
	if err != nil {
		return primedResponse, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("id_string", noteName)
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &primedResponse)
	return primedResponse, err
}

func (c *StorageClient) BulkDeleteByClient(ctx context.Context, clientID uuid.UUID, limit int) (BulkDeleteResponse, error) {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes/bulk/" + clientID.String()
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	var resp BulkDeleteResponse
	if err != nil {
		return resp, err
	}
	urlParams := req.URL.Query()
	if limit != 0 {
		urlParams.Set("limit", strconv.Itoa(limit))
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &resp)
	return resp, err
}

func (c *StorageClient) InternalDeleteNoteByID(ctx context.Context, noteID uuid.UUID) error {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	urlParams := req.URL.Query()
	urlParams.Set("note_id", noteID.String())
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

func (c *StorageClient) InternalDeleteNoteByName(ctx context.Context, noteName string) error {
	path := c.Host + "/internal" + storageServiceBasePath + "/notes"
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	urlParams := req.URL.Query()
	urlParams.Set("id_string", noteName)
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, nil)
	return err
}

// InternalSearchBySharingGroup performs an internal search to return the recordIDs for a particular sharing group.
// Sharing group defined as a subset of the access tuple: (writer_id, user_id, content_type)
// For all current uses, writer_id and user_id are the same, but must be included to take advantage of indices.
func (c *StorageClient) InternalSearchBySharingGroup(ctx context.Context, params InternalSearchBySharingTupleRequest) (*InternalSearchBySharingTupleResponse, error) {
	var result *InternalSearchBySharingTupleResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/search/sharing-group"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// OutgoingShares get outgoing shares for a given client.
func (c *StorageClient) OutgoingShares(ctx context.Context, params OutgoingShareRequest) (*OutgoingShareResponse, error) {
	var result *OutgoingShareResponse
	path := c.Host + storageServiceBasePath + "/share/outgoing"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// IncomingShares get incoming shares for a given client.
func (c *StorageClient) IncomingShares(ctx context.Context, params SearchIncomingSharesRequest) (*SearchIncomingSharesResponse, error) {
	var result *SearchIncomingSharesResponse
	path := c.Host + storageServiceBasePath + "/share/incoming"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// ProxiedAuthorization gives a list of authorizations the user has proxied out.
func (c *StorageClient) ProxiedAuthorization(ctx context.Context, params SearchAuthorizationsProxiedRequest) (*SearchAuthorizationsProxiedResponse, error) {
	var result *SearchAuthorizationsProxiedResponse
	path := c.Host + storageServiceBasePath + "/authorizer/outgoing"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GrantedAuthorizations gives a list of authorizations granted to the user.
func (c *StorageClient) GrantedAuthorizations(ctx context.Context, params SearchAuthorizedGrantedRequest) (*SearchAuthorizedGrantedResponse, error) {
	var result *SearchAuthorizedGrantedResponse
	path := c.Host + storageServiceBasePath + "/authorizer/incoming"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) WriteRecord(ctx context.Context, params Record) (*Record, error) {
	var result *Record
	path := c.Host + storageServiceBasePath + "/records"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// WriteFile writes the pending files to the pending file table, returning a pendingFileID and pendingFileURL.
// 'Compression' must be nonempty in params FileMeta, otherwise it will cause an error even though the error is not returned.
func (c *StorageClient) WriteFile(ctx context.Context, params Record) (*PendingFileResponse, error) {
	var result *PendingFileResponse
	path := c.Host + storageServiceBasePath + "/files"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

func (c *StorageClient) FileCommit(ctx context.Context, pendingFileID uuid.UUID) (*Record, error) {
	var result *Record
	path := c.Host + storageServiceBasePath + "/files/" + pendingFileID.String()
	req, err := e3dbClients.CreateRequest("PATCH", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeE3DBServiceCall(ctx, c.requester, c.E3dbAuthClient.TokenSource(), req, &result)
	return result, err
}

// New returns a new E3dbSearchIndexerClient for authenticated communication with a Search Indexer service at the specified endpoint.
func New(config e3dbClients.ClientConfig) StorageClient {
	authService := authClient.New(config)
	return StorageClient{
		Host:           config.Host,
		SigningKeys:    config.SigningKeys,
		EncryptionKeys: config.EncryptionKeys,
		ClientID:       config.ClientID,
		httpClient:     &http.Client{},
		E3dbAuthClient: &authService,
		requester:      request.ApplyInterceptors(&http.Client{}, config.Interceptors...),
	}
}

// Returns all access policies (User ID, Writer ID, Reader ID, Record Type) for a given writer ID
func (c *StorageClient) InternalListAllowedReadsByWriterID(ctx context.Context, params InternalListAllowedReadsByWriterIDRequest) (*InternalListAllowedReadsResponse, error) {
	var result *InternalListAllowedReadsResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/allowed_readers"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) InternalRecordsByWriterID(ctx context.Context, params InternalRecordsByWriterIDRequest) (*InternalRecordsByWriterIDResponse, error) {
	var result *InternalRecordsByWriterIDResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/records"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

func (c *StorageClient) InternalGetNoteInfo(ctx context.Context, noteName string) (*InternalNoteInfoResponse, error) {
	var result *InternalNoteInfoResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/notes/info"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}

	urlParams := req.URL.Query()
	if noteName != "" {
		urlParams.Set("id_string", noteName)
	}

	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// InternalClientGroupMembershipFetch is an internal endpoint used to fetch a clients membership within a group for given capabilities
func (c *StorageClient) InternalClientGroupMembershipFetch(ctx context.Context, params InternalFetchClientMembership) (*InternalFetchClientMembershipResponse, error) {
	var result *InternalFetchClientMembershipResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/groups"
	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	// Set Query Parameters
	urlParams := req.URL.Query()
	urlParams.Set("client_id", params.ClientID.String())
	for _, capability := range params.Capabilities {
		urlParams.Add("capabilities", capability)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// BulkListGroupInfo fetches a group using the specified parameters,
// returning the group and error (if any).
func (c *StorageClient) BulkListGroupInfo(ctx context.Context, params BulkListGroupInfoRequest) (*BulkListGroupInfoResponse, error) {
	var result *BulkListGroupInfoResponse
	path := c.Host + storageServiceBasePath + "/groups/bulk"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	for _, group := range params.GroupIDs {
		urlParams.Add("group_ids", group)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GroupAllowedReads fetches the allowed group reads for a writer id and content type
func (c *StorageClient) GroupAllowedReads(ctx context.Context, params AllowedGroupsForPolicyRequest) (*AllowedGroupsForPolicyResponse, error) {
	var result *AllowedGroupsForPolicyResponse
	path := c.Host + storageServiceBasePath + "/groups/allowed_readers"
	req, err := e3dbClients.CreateRequest("GET", path, params)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	for _, contentType := range params.ContentTypes {
		urlParams.Add("content_types", contentType)
	}
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// InternalGroupAllowedReads is an internal endpoint used to fetch the allowed group reads for a writer id and content type
func (c *StorageClient) InternalGroupAllowedReads(ctx context.Context, params InternalAllowedGroupsForPolicyRequest) (*InternalAllowedGroupsForPolicyResponse, error) {
	var result *InternalAllowedGroupsForPolicyResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/groups/allowed_readers"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// InternalGroupModifiedAllowedReadsBatch fetches modified allowed reads for group records
func (c *StorageClient) InternalGroupModifiedAllowedReadsBatch(ctx context.Context, params InternalSearchModifiedGroupAllowedReadsRequest) (*InternalSearchModifiedGroupAllowedReadsResponse, error) {
	var result *InternalSearchModifiedGroupAllowedReadsResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/groups/modified_allowed_reads"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// GetGroupRecordsByRecordID Fetches records shared with groups based on search query
func (c *StorageClient) GetGroupRecordsByRecordID(ctx context.Context, params GetGroupRecordsRequest) (*GetGroupRecordsResponse, error) {
	var result *GetGroupRecordsResponse
	path := c.Host + "/internal" + storageServiceBasePath + "/groups/search"
	req, err := e3dbClients.CreateRequest("POST", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// BulkDeleteRecords removes all records passed in
func (c *StorageClient) BulkDeleteRecords(ctx context.Context, params BulkRecordDeleteRequest) (*BulkRecordDeleteResponseErrors, error) {
	var result *BulkRecordDeleteResponseErrors
	path := c.Host + storageServiceBasePath + "/records/bulk/delete"
	req, err := e3dbClients.CreateRequest("DELETE", path, params)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// InternalDeleteRecords deletes all records of given clientID
func (c *StorageClient) InternalDeleteClientRecords(ctx context.Context, clientID string) (*BulkRecordDeleteResponseErrors, error) {
	var result *BulkRecordDeleteResponseErrors
	path := c.Host + "/internal" + storageServiceBasePath + "/records/client/" + clientID
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// InternalDeleteClientGroups deletes all groups of given clientID
func (c *StorageClient) InternalDeleteClientGroups(ctx context.Context, clientID string) ([]RecordError, error) {
	var result []RecordError
	path := c.Host + "/internal" + storageServiceBasePath + "/groups/client/" + clientID
	req, err := e3dbClients.CreateRequest("DELETE", path, nil)
	if err != nil {
		return result, err
	}
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err
}

// AdminListAllGroups fetches group using the specified parameters,
// returning the groups and error (if any).
func (c *StorageClient) AdminListAllGroups(ctx context.Context, params AdminListAllGroups) (*AdminListGroupsResponse, error) {
	var result *AdminListGroupsResponse
	path := c.Host + storageServiceBasePath + "/groups/realm/" + params.RealmID.String()

	req, err := e3dbClients.CreateRequest("GET", path, nil)
	if err != nil {
		return result, err
	}
	urlParams := req.URL.Query()
	urlParams.Set("nextToken", strconv.Itoa(int(params.NextToken)))
	urlParams.Set("max", strconv.Itoa(int(params.Max)))
	req.URL.RawQuery = urlParams.Encode()
	err = e3dbClients.MakeSignedServiceCall(ctx, c.requester, req, c.SigningKeys, c.ClientID, &result)
	return result, err

}
