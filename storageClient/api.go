package storageClient

import (
	"time"

	"github.com/google/uuid"
	"github.com/tozny/e3db-clients-go/pdsClient"
)

// Note is the API-level note object that mirrors the note JSON objects.
type Note struct {
	NoteID              string            `json:"note_id,omitempty"`
	IDString            string            `json:"id_string"`
	ClientID            string            `json:"client_id,omitempty"`
	Mode                string            `json:"mode"`
	RecipientSigningKey string            `json:"recipient_signing_key"`
	WriterSigningKey    string            `json:"writer_signing_key"`
	WriterEncryptionKey string            `json:"writer_encryption_key"`
	EncryptedAccessKey  string            `json:"encrypted_access_key"`
	Type                string            `json:"type"`
	Data                map[string]string `json:"data"`
	Plain               map[string]string `json:"plain"`
	FileMeta            map[string]string `json:"file_meta,omitempty"`
	EACPS               *EACP             `json:"eacp,omitempty"`
	Signature           string            `json:"signature"`
	CreatedAt           time.Time         `json:"created_at"`
	MaxViews            int               `json:"max_views,omitempty"`
	Views               int               `json:"views"`
	Expiration          time.Time         `json:"expiration,omitempty"`
	Expires             bool              `json:"expires,omitempty"`
}

// CreateGroupRequest wraps parameters needed to request creation of a group
type CreateGroupRequest struct {
	Name              string `json:"group_name"`
	PublicKey         string `json:"public_key"`
	Description       string `json:"description"`
	EncryptedGroupKey string `json:"encrypted_group_key"`
}

// Group wraps values related to managing client membership and capabilities for resources such as records.
type Group struct {
	GroupID           uuid.UUID `json:"group_id"`
	Name              string    `json:"group_name"`
	AccountID         uuid.UUID `json:"account_id"`
	PublicKey         string    `json:"public_key"`
	CreatedAt         time.Time `json:"created_at"`
	LastModified      time.Time `json:"last_modified"`
	EncryptedGroupKey string    `json:"encrypted_group_key"`
	Description       string    `json:"description"`
	MemberCount       int       `json:"member_count"`
}

// GroupAccessKeyRequest wraps the values to get or create an access key
type GroupAccessKeyRequest struct {
	GroupID            uuid.UUID `json:"group_id"`
	RecordType         string    `json:"record_type"`
	RecordID           string    `json:"record_id"`
	EncryptedAccessKey string    `json:"encrypted_access_key"`
	PublicKey          string    `json:"public_key"`
}

// ShareGroupRecordRequest wraps the values of a record for a group
type ShareGroupRecordRequest struct {
	GroupID            uuid.UUID `json:"group_id"`
	RecordType         string    `json:"record_type"`
	RecordID           string    `json:"record_id"`
	EncryptedAccessKey string    `json:"encrypted_access_key"`
	PublicKey          string    `json:"public_key"`
}

// RemoveRecordSharedWithGroupRequest wraps the values for revoking record access to a group
type RemoveRecordSharedWithGroupRequest struct {
	GroupID      uuid.UUID
	RecordType   string    `json:"record_type"`
	WriterID     uuid.UUID `json:"writer_id"`
	AuthorizerID uuid.UUID `json:"authorizer_id"`
}

// ShareGroupRecordResponse wraps the return values of sharing a record for a group
type ShareGroupRecordResponse ShareGroupRecordRequest

// DescribeGroupRequest wraps values used to look up Groups
type DescribeGroupRequest struct {
	GroupID uuid.UUID `json:"group_id"`
}

// ListGroupMembersRequest wraps the group id needed to look up group members
type ListGroupMembersRequest DescribeGroupRequest

// ListGroupsRequest look up groups for the client's account by default or optionally filter by parameters such as client ID
type ListGroupsRequest struct {
	ClientID   uuid.UUID
	GroupNames []string
	NextToken  int64
	Max        int
}

// ListGroupsResponse wraps a collection of groups
type ListGroupsResponse struct {
	Groups    []Group `json:"groups"`
	NextToken int64   `json:"next_token"`
}

// AddingCapabilityRequest wraps values used to add a capability for Groups.
type AddingCapabilityRequest struct {
	ClientID       uuid.UUID `json:"client_id"`
	Name           string    `json:"group_name"`
	CapabilityName string    `json:"capability_name"`
	AccountID      uuid.UUID `json:"account_id"`
}

// GroupMember wraps values for a client that is a member of a group.
type GroupMember struct {
	ClientID        uuid.UUID `json:"client_id"`
	MembershipKey   string    `json:"membership_key"`
	CapabilityNames []string  `json:"capability_names"`
}

// DeleteGroupMembersRequest  wraps the information of all members being removed from group provided.
type DeleteGroupMembersRequest AddGroupMembersRequest

// GetMembershipKeyRequest wraps the information to get the membership key for a client
type GetMembershipKeyRequest struct {
	GroupID uuid.UUID `json:"group_id"`
}

// ListGroupRecordsRequest wraps values needed for the request to list all records shared with a group, can filter by writer ids
type ListGroupRecordsRequest struct {
	GroupID   uuid.UUID `json:"group_id"`
	WriterIDs []string  `json:"writer_ids"`
	NextToken string
	Max       int
}

// ListGroupRecordsResponse returns all the records shared with a group and the values needed to unwrap.
type ListGroupRecordsResponse struct {
	ResultList []pdsClient.ListedRecord `json:"results"`
	NextToken  string                   `json:"next_token"`
}

// AccessKeyWrapper holds the information needed to unwrap each layer of access keys
type AccessKeyWrapper struct {
	MembershipKey string    `json:"membership_key"`
	PublicKey     string    `json:"public_key"`
	AccessKeyID   uuid.UUID `json:"access_key_id"`
}

// AddGroupMembersRequest  wraps the information of all members being added.
type AddGroupMembersRequest struct {
	GroupID      uuid.UUID     `json:"group_id"`
	GroupMembers []GroupMember `json:"group_members"`
}

// CreateMembershipKeyRequest wraps the values needed to create a membership key for clients.
type CreateMembershipKeyRequest struct {
	GroupAdminID      string
	NewMemberID       string
	EncryptedGroupKey string
	ShareePublicKey   string
}

// DeleteGroupRequest wraps values used to delete a Group.
type DeleteGroupRequest struct {
	GroupID   uuid.UUID `json:"group_id"`
	AccountID uuid.UUID `json:"account_id"`
	ClientID  uuid.UUID `json:"client_id"`
}

// ClientGroup wraps values managing client membership
type ClientGroup struct {
	GroupID       uuid.UUID `json:"group_id"`
	MembershipKey string    `json:"encrypted_membership_key"`
	ClientID      uuid.UUID `json:"client_id"`
	AuthorizerID  uuid.UUID `json:"authorizer_id"`
}

// CapabilityMap wraps values managing client capabilities for resources
type CapabilityMap struct {
	SubjectID      uuid.UUID `json:"subject_id"`
	ResourceID     uuid.UUID `json:"resource_id"`
	SubjectType    string    `json:"subject_type"`
	ResourceType   string    `json:"resource_type"`
	CapabilityName string    `json:"capability_name"`
}

type EACP struct {
	EmailEACP      *EmailEACP      `json:"email_eacp,omitempty"`
	LastAccessEACP *LastAccessEACP `json:"last_access_eacp,omitempty"`
	ToznyOTPEACP   *ToznyOTPEACP   `json:"tozny_otp_eacp,omitempty"`
	TozIDEACP      *TozIDEACP      `json:"tozid_eacp,omitempty"`
}

type EmailEACP struct {
	EmailAddress             string            `json:"email_address"`
	Template                 string            `json:"template"`
	ProviderLink             string            `json:"provider_link"`
	TemplateFields           map[string]string `json:"template_fields"`
	DefaultExpirationMinutes int               `json:"default_expiration_minutes"`
}

type LastAccessEACP struct {
	LastReadNoteID uuid.UUID `json:"last_read_note_id"`
}

// ToznyOTPEACP is an EACP that allows a Tozny hosted service to prime an EACP with a
// one time password. If attaching Include must be set to true.
type ToznyOTPEACP struct {
	Include bool `json:"include"`
}

// TozIDEACP wraps an EACP requiring the proxying of a one time password OTP
// embedded as the nonce claim for a valid & signed TozID realm auth JWT token
type TozIDEACP struct {
	RealmName string `json:"realm_name"`
}

type BulkDeleteResponse struct {
	ClientID    uuid.UUID `json:"client_id"`
	DeleteCount int       `json:"delete_count"`
}

type OTPRequest struct {
	ExpiryMinutes int `json:"expiry_minutes"`
}

// PrimeRequestBody is used in EACP priming requests. These requests allow
// preparation of an EACP by an authorized entity that is not the signed note recipient
type PrimeRequestBody struct {
	OTP *OTPRequest `json:"otp"`
}

type OTPResponse struct {
	Password string `json:"password"`
}

// PrimeResponseBody is returned from EACP priming requests. It will always return the NoteID and responses for
// EACP primings that supply them i.e. OTPResponse for an ToznyOTPEACP
type PrimeResponseBody struct {
	NoteID   uuid.UUID   `json:"note_id"`
	ToznyOTP OTPResponse `json:"otp"`
}

type ChallengeRequest struct {
	EmailEACPChallenge EmailEACPChallengeRequest `json:"email_eacp"`
	TozIDEACPChallenge TozIDEACPChallengeRequest `json:"tozid_eacp"`
}

type EmailEACPChallengeRequest struct {
	TemplateName  string `json:"template_name"`
	ExpiryMinutes int    `json:"expiry_minutes"`
}

// TozIDEACPChallengeRequest wraps parameters needed to activate a TozID EACP on a note.
type TozIDEACPChallengeRequest struct {
	ExpirySeconds int64 `json:"expiry_seconds"`
}

// ChallengeResponse wraps parameters for all activated challenges on a note.
type ChallengeResponse struct {
	EmailEACPChallenge *EmailEACPChallengeResponse `json:"email_eacp,omitempty"`
	TozIDEACPChallenge *TozIDEACPChallengeResponse `json:"tozid_eacp,omitemtpy"`
}

type EmailEACPChallengeResponse struct {
	ExpiresAt    time.Time `json:"expires_at"`
	TemplateName string    `json:"template_name"`
}

// TozIDEACPChallengeRequest wraps parameters for an activated TozID EACP on a note.
type TozIDEACPChallengeResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	// The `nonce` claim that must be present in a TozID JWT signed OIDC ID token issued as part of a valid TozID realm login session that also contains TozID as the authorizing party (`azp`) claim.
	TozIDLoginTokenNonce string `json:"tozid_login_token_nonce"`
	RealmName            string `json:"realm_name"`
}

// Record struct
type Record struct {
	Metadata        Meta              `json:"meta"`
	Data            map[string]string `json:"data"`
	RecordSignature string            `json:"rec_sig,omitempty"`
}

// Meta contains meta-information about an E3DB record, such as
// who wrote it, when it was written, and the type of the data stored.
// This is a copy of the PDS client Meta, except that it enforces UUID typing to match the database
type Meta struct {
	RecordID     uuid.UUID         `json:"record_id,omitempty"`
	WriterID     uuid.UUID         `json:"writer_id"`
	UserID       uuid.UUID         `json:"user_id"`
	Type         string            `json:"type"`
	Plain        map[string]string `json:"plain"`
	Created      time.Time         `json:"created"`
	LastModified time.Time         `json:"last_modified"`
	Version      uuid.UUID         `json:"version,omitempty"`
	// Certain pds endpoints such as WriteRecord return 400 Bad Request if this key is present in the JSON
	// https://www.sohamkamani.com/blog/golang/2018-07-19-golang-omitempty/
	FileMeta *FileMeta `json:"file_meta,omitempty"`
}

// FileMeta contains meta-information about files associated with E3DB Large File Records,
// such as file name, S3 url, and other file data.
type FileMeta struct {
	FileURL     string `json:"file_url,omitempty"`
	FileName    string `json:"file_name,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Compression string `json:"compression,omitempty"`
	Checksum    string `json:"checksum,omitempty"`
}

// PendingFileResponse contains the pendingFileID and the fileURL to post the file data to.
type PendingFileResponse struct {
	PendingFileID uuid.UUID `json:"id"`
	FileURL       string    `json:"file_url"`
}

// InternalSearchBySharingTupleRequest internal request to v2 search for record ids by sharing group
// primarily used by the reconciler
type InternalSearchBySharingTupleRequest struct {
	SharingTuples []SharingTuple `json:"sharing_tuples"`
	NextToken     int64          `json:"next_token"`
	Limit         int            `json:"limit"`
}

// SharingTuple sharing tuple for writers that each record falls within
type SharingTuple struct {
	UserID      string `json:"user_id"`
	WriterID    string `json:"writer_id"`
	ContentType string `json:"content_type"`
}

// InternalSearchBySharingTupleResponse response from internal request for v2 search for record ids by sharing group
// primarily used by the reconciler
type InternalSearchBySharingTupleResponse struct {
	RecordIDs []string `json:"record_ids"`
	NextToken int64    `json:"next_token"`
}

// SearchAuthorizationsProxiedRequest request to search proxied authorizations (outgoing).
type SearchAuthorizationsProxiedRequest struct {
	NextToken    int64  `json:"next_token"`
	Limit        int    `json:"limit"`
	AuthorizerID string `json:"authorizer_id"`
	RecordType   string `json:"record_type"`
}

// SearchAuthorizationsProxiedResponse response returned from a search proxied authorizations call.
type SearchAuthorizationsProxiedResponse struct {
	Authorizations []AuthorizationsProxiedPolicy `json:"authorizations"`
	NextToken      int64                         `json:"next_token"`
}

// AuthorizationsProxiedPolicy single proxied out policy definition.
type AuthorizationsProxiedPolicy struct {
	AuthorizerID string    `json:"authorizer_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
	RecordType   string    `json:"record_type"`
}

// SearchAuthorizedGrantedRequest request to search for granted authorizations (incoming).
type SearchAuthorizedGrantedRequest struct {
	NextToken    int64  `json:"next_token"`
	Limit        int    `json:"limit"`
	AuthorizedBy string `json:"authorized_by"`
	RecordType   string `json:"record_type"`
}

// SearchAuthorizedGrantedResponse response returned from a search granted authorizations call.
type SearchAuthorizedGrantedResponse struct {
	Authorizations []AuthorizedGrantedPolicy `json:"authorizations"`
	NextToken      int64                     `json:"next_token"`
}

// AuthorizedGrantedPolicy single granted policy definition.
type AuthorizedGrantedPolicy struct {
	AuthorizedBy string    `json:"authorized_by"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
	RecordType   string    `json:"record_type"`
}

// SearchIncomingSharesRequest search request for getting incoming shares.
type SearchIncomingSharesRequest struct {
	NextToken  int64  `json:"next_token"`
	Limit      int    `json:"limit"`
	WriterID   string `json:"writer_id"`
	RecordType string `json:"record_type"`
}

// SearchIncomingSharesResponse search response for incoming shares.
type SearchIncomingSharesResponse struct {
	Shares    []IncomingSharePolicy `json:"shares"`
	NextToken int64                 `json:"next_token"`
}

// IncomingSharePolicy policy for single incoming share.
type IncomingSharePolicy struct {
	WriterID   string `json:"writer_id"`
	RecordType string `json:"record_type"`
}

// OutgoingShareRequest search request for getting outgoing shares.
type OutgoingShareRequest struct {
	NextToken  int64  `json:"next_token"`
	Limit      int    `json:"limit"`
	ReaderID   string `json:"reader_id"`
	RecordType string `json:"record_type"`
}

// OutgoingShareResponse response to getting outgoing shares.
type OutgoingShareResponse struct {
	Shares    []OutgoingSharePolicy `json:"shares"`
	NextToken int64                 `json:"next_token"`
}

// OutgoingSharePolicy policy for single outgoing share
type OutgoingSharePolicy struct {
	ReaderID   string `json:"reader_id"`
	RecordType string `json:"record_type"`
}
