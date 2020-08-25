package storageClient

import (
	"time"

	"github.com/google/uuid"
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
	Size        int    `json:"size,omitempty"`
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
