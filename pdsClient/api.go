package pdsClient

import (
    "time"
)

// RegisterClientRequest represents a request to register a client.
type RegisterClientRequest struct {
    Email      string    `json:"email"`
    PublicKey  ClientKey `json:"public_key"`
    PrivateKey ClientKey `json:"private_key"`
}

// RegisterClientResponse represents a response from an attempt to register a client.
type RegisterClientResponse struct {
    ClientID  string `json:"client_id"`
    APIKeyID  string `json:"api_key_id"`
    APISecret string `json:"api_secret"`
}

// Record wraps details about an E3db API record object.
type Record struct {
    Metadata Meta              `json:"meta"`
    Data     map[string]string `json:"data"`
}

// PutAccessKeyRequest represents a request to put an access key into e3db.
type PutAccessKeyRequest struct {
    WriterID           string
    UserID             string
    ReaderID           string
    RecordType         string
    EncryptedAccessKey string `json:"eak"`
}

// PutAccessKeyResponse represents a response from trying to put an access key into e3db.
type PutAccessKeyResponse struct {
    SignerID            string `json:"signer_id"`
    SignerSigningKey    string `json:"signer_signing_key"`
    AuthorizerPublicKey string `json:"authorizer_public_key"`
    EncryptedAccessKey  string `json:"eak"`
}

// WriteRecordRequest represents a request to write a record via the e3db api.
type WriteRecordRequest = Record

// WriteRecordResponse represents a response from trying to write a record via the e3db api.
type WriteRecordResponse = Record

// ListRecordsRequest represents a valid ListRecord call to the PDS service.
type ListRecordsRequest struct {
    Count       int  `json:"count"`                  //The maximum number of records to return.
    IncludeData bool `json:"include_data,omitempty"` //If true, include record data with results.

    WriterIDs         []string          `json:"writer_ids,omitempty"`    //If not empty, limit results to records written by the given set of IDs.
    UserIDs           []string          `json:"user_ids,omitempty"`      //If not null, limit results to records about given set of IDs.
    RecordIDs         []string          `json:"record_ids,omitempty"`    //If not empty, limit results to the records specified.
    ContentTypes      []string          `json:"content_types,omitempty"` //If not empty, limit results to records of the given types.
    AfterIndex        int               `json:"after_index,omitempty"`   //If greater than 0, limit results to the records appearing "after" the given index.
    Plain             map[string]string `json:"plain,omitempty"`
    IncludeAllWriters bool              `json:"include_all_writers,omitempty"` //If true, include all records shared with this client.
}

// Meta contains meta-information about an E3DB record, such as
// who wrote it, when it was written, and the type of the data stored.
type Meta struct {
    RecordID     string            `json:"record_id,omitempty"`
    WriterID     string            `json:"writer_id"`
    UserID       string            `json:"user_id"`
    Type         string            `json:"type"`
    Plain        map[string]string `json:"plain"`
    Created      time.Time         `json:"created"`
    LastModified time.Time         `json:"last_modified"`
    Version      string            `json:"version,omitempty"`
}

// GetEAKResponse contains the api representation of fetching an encrypted access key.
type GetEAKResponse struct {
    EAK                 string    `json:"eak"`
    AuthorizerID        string    `json:"authorizer_id"`
    AuthorizerPublicKey ClientKey `json:"authorizer_public_key"`
}

// ClientKey contains a cryptographic key for use in client operations.
type ClientKey struct {
    Curve25519 string `json:"curve25519"`
}

// ListedRecord contains the api List
// representation for a record
type ListedRecord struct {
    Metadata  Meta              `json:"meta"`
    Data      map[string]string `json:"record_data"`
    AccessKey *GetEAKResponse   `json:"access_key"`
}

// InternalGetRecordResponse wraps the api response from a
// GET internal/v1/records call
type InternalGetRecordResponse struct {
    Metadata Meta `json:"meta"`
}

// ListRecordResults contains a set of listed records as a result of making a ListRecord call.
type ListRecordsResult struct {
    Results   []ListedRecord `json:"results"`
    LastIndex int            `json:"last_index"`
}
