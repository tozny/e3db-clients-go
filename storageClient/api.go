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
	EmailAddress   string            `json:"email_address"`
	Template       string            `json:"template"`
	ProviderLink   string            `json:"provider_link"`
	TemplateFields map[string]string `json:"template_fields"`
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
type TozIDEACP struct{}

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
	TemplateName string `json:"template_name"`
	OTPRequest
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
}
