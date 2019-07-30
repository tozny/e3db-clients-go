package storageClient

import (
	"time"
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
	Signature           string            `json:"signature"`
	CreatedAt           time.Time         `json:"created_at"`
	MaxViews            int               `json:"max_views,omitempty"`
	Views               int               `json:"views"`
	Expiration          time.Time         `json:"expiration,omitempty"`
	Expires             bool              `json:"expires,omitempty"`
}
