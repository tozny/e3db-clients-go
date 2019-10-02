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

type BulkDeleteResponse struct {
	ClientID    uuid.UUID `json:"client_id"`
	DeleteCount int       `json:"delete_count"`
}
